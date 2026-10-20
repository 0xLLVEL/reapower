"""Stage 5 - a local-account entry point wired into the launcher's own account menu.

Four edits and one new file. Unlike stage 4, three of these *add* bytes, so the asar
header has to be rewritten: an entry's offset is absolute in the data section, and
growing dist-electron/electron/main.js moves every file packed after it. asar_repack
was proved lossless first by round-tripping a no-op replacement through it and
comparing all 1286 embedded files byte for byte.

The add path is not a file writer. It reaches the launcher's real auth module:

  window.lunar.auth.addAccount({username})
    -> ipcRenderer.invoke("auth:addAccount", payload)
    -> the patched handler in ZAe.onSetup
    -> ZAe.addLocalAccount
    -> _Ee(...)                 writes accounts.json through the launcher's own store
    -> store.dispatch(KAe(...)) updates the in-memory profile list

so the file on disk and the state the launcher holds cannot drift apart, which is the
failure mode that forced account-manager.ps1 to insist on a closed launcher.

_Ee(e,t,n,r,i,a,o,s) takes profileId, name, accessToken, expiresAt, refreshToken, type,
remoteId, localId. The v4 shape of profileId is load-bearing: the launch path normalises
through mN(), which only rewrites a UUID that already passes the v4 test, and a value it
does not recognise leaves getAccount() missing and the launch dead with SR.NO_ACCOUNT.
The 12h expiry matches stage 2 - a past date triggers the refresh path and comes back as
INVALID_SESSION, and anything past the 14-day window is rejected outright.
"""

import struct
import json
import os
import sys
import shutil
import hashlib

ASAR = r"C:\Users\ezan\AppData\Local\Programs\Lunar Client\resources\app.asar"
HERE = os.path.dirname(os.path.abspath(__file__))

ENTRY_MODULE = "/dist/assets/rat-accounts.js"

# every file this patcher is allowed to change - anything else differing means the
# rebuild lost data somewhere and the result must not be installed
SPLICE_TARGETS = [
    "/dist-electron/electron/main.js",
    "/dist-electron/preload/launcher/index.js",
    "/dist/html/main.html",
]


def sha8(b):
    return hashlib.sha256(b).hexdigest()[:8]


def read_container(path):
    with open(path, "rb") as f:
        head = f.read(16)
        if struct.unpack("<I", head[0:4])[0] != 4:
            raise SystemExit("not an asar")
        block = struct.unpack("<I", head[4:8])[0]
        json_len = struct.unpack("<I", head[12:16])[0]
        tree = json.loads(f.read(json_len).decode("utf-8"))
        # block + 8 is where the data section begins - derived, not guessed. Rounding up
        # to an alignment would read every file from the wrong offset whenever the
        # header length is not a multiple of 4.
        data_start = block + 8
    return tree, data_start


def walk(node, base=""):
    for name, child in node.get("files", {}).items():
        full = base + "/" + name
        if "files" in child:
            for item in walk(child, full):
                yield item
        else:
            yield full, child


def find_node(tree, want):
    for p, n in walk(tree):
        if p == want:
            return n
    return None


def ensure_dir(tree, path):
    parts = path.strip("/").split("/")
    cur = tree
    for part in parts[:-1]:
        cur = cur.setdefault("files", {}).setdefault(part, {"files": {}})
        if "files" not in cur:
            raise SystemExit("path clash at %s" % part)
    cur.setdefault("files", {})
    return cur["files"], parts[-1]


def splice(text, find, repl, label):
    n = text.count(find)
    if n != 1:
        raise SystemExit("%s: %d occurrence(s) of the source span, expected 1" % (label, n))
    print("  %-22s +%d B  %s" % (label, len(repl) - len(find), find[:58] + ("..." if len(find) > 58 else "")))
    return text.replace(find, repl, 1)


# --------------------------------------------------------------------------- spans

# The handler is registered through sE.handle, which is
#     handle(e,n){ipcMain.handle(`${this.prefix}:${e}`,n)}
# so the payload the renderer invokes with arrives as the second argument. The first is
# the IpcMainInvokeEvent, which is why the signature has to become (e,t) and not (e).
HANDLER_FIND = (
    "this.handle(`addAccount`,async()=>{await this.addAccount(x_.launcher_add)"
)
HANDLER_REPL = (
    "this.handle(`addAccount`,async(e,t)=>{"
    "if(t&&t.username)return this.addLocalAccount(t);"
    "await this.addAccount(x_.launcher_add)"
)

# Inserted directly ahead of the existing addAccount(e) so both live on the same class.
# ``Xbox`` is written as a literal rather than as gEe.Xbox: the enum is declared
# thousands of bytes away in the bundle and its scope relative to this class is not
# knowable without running it, while the value is a plain string in the account record.
METHOD_ANCHOR = "name}.`),a}async addAccount(e){"

# `accessTokenExpiresAt` has to be an ISO string, not epoch milliseconds. The store
# re-reads accounts.json through the valibot schema `mEe` on every load, and that field
# is declared `string()` - a number fails the parse, so the read handler reports
# "Accounts file is invalid, creating new one..." and replaces the document with an empty
# map. That is a total wipe of every account, not a rejection of the one being added, and
# it fires on the NEXT load rather than at the write, which is what made it look like a
# switch failure. The write itself logs "Successfully added" four seconds before the file
# is discarded.
#
# 13 days, not 12 hours. `executeWithAccessToken` refreshes when this timestamp is before
# now, and a refresh goes out over the network to a session that cannot be established
# offline - so a lapsed expiry does not degrade, it makes the account unlaunchable until
# someone refreshes it. The 14-day ceiling sits on `iat`, which is read out of the token;
# a random base64url accessToken has no `iat` and the check reads it as null, which
# passes.
METHOD_BODY = (
    "name}.`),a}"
    "async addLocalAccount(t){"
    "let n=(0,R.randomUUID)(),"
    "r=Buffer.from((0,R.pseudoRandomBytes)(64)).toString(`base64url`),"
    "i=new Date(Date.now()+11232e5).toISOString(),"
    "o=(0,R.randomBytes)(16).toString(`hex`),"
    "s=mN((0,R.randomUUID)());"
    "return await _Ee(n,t.username,r,i,void 0,`Xbox`,o,s),"
    "Z.store.dispatch(KAe({uuid:n,username:t.username,localId:s,loading:!1,invalid:!1})),"
    "n}"
    "async addAccount(e){"
)

PRELOAD_FIND = "_={async addAccount(){return await u.ipcRenderer.invoke(`auth:addAccount`)}"
PRELOAD_REPL = "_={async addAccount(e){return await u.ipcRenderer.invoke(`auth:addAccount`,e)}"

# A classic script, not type="module": the file has no imports or exports, so module
# semantics buy nothing and only add defer timing and module-CORS as ways to fail
# silently. Relative, matching how main.html references its own bundle - an absolute src
# on a file:// origin resolves against the filesystem root and 404s, which is how the
# first revision never ran at all.
HTML_FIND = "</body>"
HTML_REPL = '<script src="../assets/rat-accounts.js"></script>' + "</body>"


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else ASAR
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "stage5.asar")

    tree, data_start = read_container(src)
    with open(src, "rb") as f:
        original = f.read()

    def read_entry(path):
        n = find_node(tree, path)
        if n is None:
            raise SystemExit("missing entry: %s" % path)
        off = data_start + int(n["offset"])
        return original[off : off + int(n["size"])]

    print("asar     : %s" % src)
    print("sha256   : %s   %d bytes" % (sha8(original), len(original)))
    print()
    print("splices")

    mainjs = read_entry("/dist-electron/electron/main.js").decode("utf-8")
    mainjs = splice(mainjs, HANDLER_FIND, HANDLER_REPL, "main.handler")
    if mainjs.count(METHOD_ANCHOR) != 1:
        raise SystemExit("main.method: anchor not unique")
    print("  %-22s +%d B  %s" % ("main.method", len(METHOD_BODY) - len(METHOD_ANCHOR), "addLocalAccount inserted"))
    mainjs = mainjs.replace(METHOD_ANCHOR, METHOD_BODY, 1)

    preload = read_entry("/dist-electron/preload/launcher/index.js").decode("utf-8")
    preload = splice(preload, PRELOAD_FIND, PRELOAD_REPL, "preload.auth")

    html = read_entry("/dist/html/main.html").decode("utf-8")
    if html.count(HTML_FIND) != 1:
        raise SystemExit("main.html: </body> not unique")
    print("  %-22s +%d B  %s" % ("main.html", len(HTML_REPL) - len(HTML_FIND), "<script> tag for the module"))
    html = html.replace(HTML_FIND, HTML_REPL, 1)

    with open(os.path.join(HERE, "rat-accounts.js"), "rb") as f:
        module = f.read()

    print()
    print("new file : %s   %d B   sha %s" % (ENTRY_MODULE, len(module), sha8(module)))

    replacements = {
        "/dist-electron/electron/main.js": mainjs.encode("utf-8"),
        "/dist-electron/preload/launcher/index.js": preload.encode("utf-8"),
        "/dist/html/main.html": html.encode("utf-8"),
    }

    # put the module in the tree, then rewrite every embedded file in one pass.
    #
    # The new entry MUST be in `replacements`. emit() treats anything absent as an
    # existing file and slices it out of the old data section at whatever offset the tree
    # carries - a fresh node was given offset "0", so it read the first N bytes of the
    # packed bundle instead. That N is close to the module's length, so size, offset,
    # tree shape and every spliced file all verified clean while the entry held the head
    # of an unrelated asset. Three installs shipped a PNG behind this tag before the
    # content was read back and the signature spotted.
    files, name = ensure_dir(tree, ENTRY_MODULE)
    if name in files and "files" in files[name]:
        raise SystemExit("entry path is a directory")
    replacements[ENTRY_MODULE] = module
    files[name] = {"size": len(module), "offset": "0"}

    # snapshot every original file before emit() rewrites the offsets in place - the
    # tree is mutated as it is walked, so reading originals afterwards would use the new
    # offsets against the old byte array and compare the wrong slices
    originals = {}
    for p, n in walk(tree):
        # the new module is already in the tree at this point, so it would otherwise be
        # snapshotted at offset "0" and read back as the head of the old data section
        if n.get("unpacked") or p == ENTRY_MODULE:
            continue
        off = data_start + int(n["offset"])
        originals[p] = original[off : off + int(n["size"])]

    data = bytearray()

    def emit(node, base=""):
        for fname, child in node.get("files", {}).items():
            full = base + "/" + fname
            if "files" in child:
                emit(child, full)
                continue
            if child.get("unpacked"):
                continue
            if full in replacements:
                blob = replacements[full]
                child["size"] = len(blob)
            else:
                off = data_start + int(child["offset"])
                blob = original[off : off + int(child["size"])]
            child["offset"] = str(len(data))
            data.extend(blob)

    emit(tree)

    # No padding, ever. [4:8] is the size of the block from byte 8, so data_start is
    # [4:8] + 8 and the header runs right up to it. Trailing NULs after the JSON would
    # be inside the length the reader hands to the parser, and both Python's json and
    # Electron's JSON.parse reject extra data - a header that parses in one reader and
    # not the other is a launcher that will not start. The original container reports an
    # offset alignment of 1, so there is nothing to align to anyway.
    header = json.dumps(tree, separators=(",", ":")).encode("utf-8")

    body = bytearray()
    body += struct.pack("<I", 4)
    body += struct.pack("<I", 8 + len(header))
    body += struct.pack("<I", 4 + len(header))
    body += struct.pack("<I", len(header))
    body += header
    body += data

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(body)

    print()
    print("written  : %s" % dst)
    print("sha256   : %s   %d bytes" % (sha8(bytes(body)), len(body)))
    print()

    # verify from disk, not from memory
    print("verify")
    t2, d2 = read_container(dst)
    e2 = {}
    with open(dst, "rb") as f2:
        for p, n in walk(t2):
            if n.get("unpacked"):
                continue
            f2.seek(d2 + int(n["offset"]))
            e2[p] = f2.read(int(n["size"]))

    diffs = []
    for p in sorted(originals):
        if p == ENTRY_MODULE:
            continue
        if p not in e2:
            diffs.append((p, "missing"))
        elif e2[p] != originals[p]:
            diffs.append((p, "content"))

    added = sorted(set(e2) - set(originals))

    # The new file has no counterpart to compare against, so its bytes are checked
    # against what was meant to be written. Absence of a diff elsewhere says nothing
    # about whether this entry landed - which is exactly how a PNG got installed here.
    if ENTRY_MODULE in e2:
        got = e2[ENTRY_MODULE]
        if got == module:
            print("  module content     : OK   %d bytes, sha %s" % (len(got), sha8(got)))
        else:
            print("  module content     : WRONG  expected %d bytes sha %s" % (len(module), sha8(module)))
            print("                       got      %d bytes sha %s" % (len(got), sha8(got)))
            print("                       first 16 bytes: %r" % got[:16])
            diffs.append((ENTRY_MODULE, "module-content"))
    else:
        print("  module content     : MISSING")
        diffs.append((ENTRY_MODULE, "module-missing"))

    print("  entries            : %d  (was %d)" % (len(e2), len(originals)))
    print("  added              : %s" % (", ".join(added) or "none"))
    print("  changed in content : %d" % len(diffs))
    for p, why in diffs[:12]:
        print("    %-52s %s" % (p, why))
    print()
    # The three spliced files are meant to differ, so "no diffs" is not the success
    # condition - the condition is that nothing *else* moved. One wrong byte in a file
    # that was not touched is what a broken rebuild looks like.
    want_changed = sorted(SPLICE_TARGETS)
    got_changed = sorted(p for p, _ in diffs)
    ok = got_changed == want_changed and added == [ENTRY_MODULE]
    print("expected changed : %s" % ", ".join(want_changed))
    print("actual   changed : %s" % (", ".join(got_changed) or "none"))
    print("expected added   : %s" % ENTRY_MODULE)
    print("actual   added   : %s" % (", ".join(added) or "none"))
    print()
    print("verdict  : %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
