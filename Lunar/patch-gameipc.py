#!/usr/bin/env python3
"""Stage 7 - launcher GameIPC: route the game's account actions to local accounts.

The game reaches the launcher over GameIPC for two things, and stock code sends both
down the Microsoft device-code path:

  AddAccount()     auth.addAccount(game_add)   opens login.microsoftonline.com
  RefreshAccount()  auth.initAuth(game_switch)  the switch itself, which is already fine

The overlay could not be fixed alone. A cracked account reaches the launcher here, and
this is the only layer that can write accounts.json.

Three edits, all inside one embedded file, so a single repack covers them:

  add-account-local      AddAccount creates a local Xbox account instead of starting the
                         Microsoft flow. The GameIPC AddAccountRequest protobuf carries no
                         fields at all, so no username can arrive with it - the name is
                         minted here. addLocalAccount does the rest: it writes the file,
                         marks the new entry active and dispatches the store.
  add-account-refresh    arg 5 of _Ee is refreshToken and addLocalAccount passed void 0.
                         The game adopts an account as current only when accessToken and
                         refreshToken are both non-null, so a token-less account could be
                         added and then never selected.
  refresh-entry-log      log the uuid on arrival and compare like for like. minecraftProfile.id
                         is dashed while n is normalised, so the old !== was always true and
                         every refresh reported game_switch, even for the current account.

Container handling is deliberately local rather than imported from asar-repack.py. That
tool rounds data_start up to a multiple of 4, and this header length is not one: the
result is a three byte shift that reads every entry mid-file. patch-accounts.py already
documents the same finding, so the reader here is block + 8 and the writer emits no
padding at all.

Usage: python patch-gameipc.py [--status|--apply|--revert]
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

ASAR = r"C:\Users\ezan\AppData\Local\Programs\Lunar Client\resources\app.asar"
BACKUP = os.path.join(
    os.environ["LOCALAPPDATA"], "LunarPatch", "backup", "app.asar.s7.pristine"
)
ENTRY = "/dist-electron/electron/main.js"
WORK = os.path.join(os.environ["LOCALAPPDATA"], "Temp", "opencode", "lunar", "stage7")

SITES = [
    {
        "name": "add-account-local",
        "note": "GameIPC AddAccount mints a local Xbox account; no Microsoft window",
        "find": (
            "try{return await e.addAccount(x_.game_add),"
            "SQ.AddAccountResponse.create({success:!0})}"
        ),
        "repl": (
            "try{return await e.addLocalAccount({username:"
            "`Cracked${Math.random().toString(36).slice(2,8)}`}),"
            "SQ.AddAccountResponse.create({success:!0})}"
        ),
    },
    {
        "name": "add-account-refresh",
        "note": "refreshToken for locally added accounts; game ignores token-less entries",
        "find": "_Ee(n,t.username,r,i,void 0,`Xbox`,o,s)",
        "repl": (
            "_Ee(n,t.username,r,i,"
            "Buffer.from((0,R.pseudoRandomBytes)(64)).toString(`base64url`),"
            "`Xbox`,o,s)"
        ),
    },
    {
        "name": "refresh-entry-log",
        "note": "uuid logged on arrival; initiator compared on normalised ids",
        "find": (
            "let n=mN(_N(e.uuid)),r=await t.getAccount(),"
            "i=r&&r.minecraftProfile.id!==n;try{return await t.initAuth("
            "i?x_.game_switch:x_.game_init,n),"
        ),
        "repl": (
            "let n=mN(_N(e.uuid));ER.info("
            "`[GameIPC] RefreshAccount for uuid ${n}`);"
            "let r=await t.getAccount(),i=r&&mN(r.minecraftProfile.id)!==n;"
            "try{return await t.initAuth(i?x_.game_switch:x_.game_init,n),"
        ),
    },
]


def sha8(b):
    return hashlib.sha256(b).hexdigest()[:16]


def read_container(path):
    with open(path, "rb") as f:
        head = f.read(16)
        if struct.unpack("<I", head[0:4])[0] != 4:
            raise SystemExit("not an asar")
        block = struct.unpack("<I", head[4:8])[0]
        json_len = struct.unpack("<I", head[12:16])[0]
        tree = json.loads(f.read(json_len).decode("utf-8"))
        # block + 8 is where the data section begins - derived, not guessed. Rounding
        # up to an alignment would read every file from the wrong offset, which is
        # exactly how asar-repack.py misreads this container by three bytes.
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


def find_node(tree, path):
    node = tree
    for part in path.strip("/").split("/"):
        if "files" not in node:
            return None
        node = node["files"].get(part)
        if node is None:
            return None
    return node


def load_entry(path):
    tree, data_start = read_container(path)
    node = find_node(tree, ENTRY)
    if node is None or node.get("unpacked"):
        raise SystemExit("missing entry: %s" % ENTRY)
    off = data_start + int(node["offset"])
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(int(node["size"]))


def reverse_spans():
    return [
        {
            "name": s["name"],
            "note": s["note"],
            "find": s["repl"],
            "repl": s["find"],
        }
        for s in SITES
    ]


def report(text):
    print("asar    :", ASAR)
    print("entry   :", ENTRY, " bytes:", len(text.encode("utf-8")))
    print("backup  :", "present" if os.path.isfile(BACKUP) else "ABSENT")
    print()
    bad = 0
    for site in SITES:
        found = text.count(site["find"])
        done = text.count(site["repl"])
        if done == 1 and found == 0:
            status = "APPLIED"
        elif found == 1 and done == 0:
            status = "pending"
            bad += 1
        elif found == 0 and done == 0:
            status = "MISSING"
            bad += 1
        else:
            status = "AMBIGUOUS(find=%d,done=%d)" % (found, done)
            bad += 1
        print("  %-22s %-30s %s" % (site["name"], status, site["note"]))
    print()
    if bad == 0:
        print("result : clean")
        return 0
    if bad == len(SITES):
        print("result : untouched")
        return 0
    print("result : %d site(s) not clean" % bad)
    return 1


def splice(text, spans, errors, direction):
    changed = 0
    for site in spans:
        found = text.count(site["find"])
        done = text.count(site["repl"])
        if done == 1 and found == 0:
            print("  %-22s already %s" % (site["name"], "applied" if direction > 0 else "reverted"))
            continue
        if found != 1:
            errors.append("%s: %d occurrence(s), want 1" % (site["name"], found))
            continue
        delta = len(site["repl"]) - len(site["find"])
        text = text.replace(site["find"], site["repl"], 1)
        changed += 1
        print("  %-22s %s (%+d bytes)  %s" % (site["name"], "applied" if direction > 0 else "reverted", delta, site["note"]))
    return text, changed


def repack(src, dst, replacements):
    """Rebuild the container. Header runs straight into the data section, no padding."""
    with open(src, "rb") as f:
        original = f.read()
    tree, data_start = read_container(src)

    # snapshot every original file before emit() rewrites offsets in place - the tree
    # is mutated as it is walked, so reading afterwards would compare new offsets
    # against the old byte array
    originals = {}
    for p, node in walk(tree):
        if node.get("unpacked") or p in replacements:
            continue
        off = data_start + int(node["offset"])
        originals[p] = original[off : off + int(node["size"])]

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

    # verify from disk, not from memory
    t2, d2 = read_container(dst)
    e2 = {}
    with open(dst, "rb") as f2:
        for p, node in walk(t2):
            if node.get("unpacked"):
                continue
            f2.seek(d2 + int(node["offset"]))
            e2[p] = f2.read(int(node["size"]))

    diffs = []
    for p in sorted(originals):
        if p not in e2:
            diffs.append((p, "missing"))
        elif e2[p] != originals[p]:
            diffs.append((p, "content"))
    for p in sorted(replacements):
        if p not in e2:
            diffs.append((p, "missing"))
        elif e2[p] != replacements[p]:
            diffs.append((p, "content"))

    return len(originals), len(replacements), len(diffs), diffs


def install(built):
    with open(built, "rb") as f:
        blob = f.read()
    if not os.path.isfile(BACKUP):
        os.makedirs(os.path.dirname(BACKUP), exist_ok=True)
        shutil.copy2(ASAR, BACKUP)
        print("backup ->", BACKUP)
    with open(ASAR, "wb") as f:
        f.write(blob)
    print("install ->", ASAR)
    print("sha256  :", sha8(blob), len(blob), "bytes")


def cmd_apply(direction, spans, label):
    text = load_entry(ASAR).decode("utf-8")
    errors = []
    print("asar    :", ASAR, "  sha", sha8(open(ASAR, "rb").read()))
    print("entry   :", ENTRY, " bytes:", len(text.encode("utf-8")))
    print()
    print(label)
    text, changed = splice(text, spans, errors, direction)
    if errors:
        for err in errors:
            print("  ERROR", err)
        return 2

    if changed == 0:
        print()
        print("nothing to do")
        return 0

    os.makedirs(WORK, exist_ok=True)
    patched = os.path.join(WORK, "main.js")
    with open(patched, "wb") as f:
        f.write(text.encode("utf-8"))

    # A bad splice here would be a syntax error the launcher only discovers at boot.
    check = subprocess.run(["node", "--check", patched], capture_output=True)
    if check.returncode != 0:
        print("node --check FAILED")
        print(check.stderr.decode("utf-8", "replace")[:2000])
        return 3
    print("  node --check OK")

    built = os.path.join(WORK, "app.asar.built")
    orig_n, new_n, n_diff, diffs = repack(ASAR, built, {ENTRY: text.encode("utf-8")})
    print("  originals compared : %d" % orig_n)
    print("  replacements       : %d" % new_n)
    print("  diffs              : %d" % n_diff)
    for path, why in diffs[:20]:
        print("    %-60s %s" % (path, why))
    # every entry that was not replaced must be byte-identical, and the one that was
    # must read back as exactly the bytes handed in - so a clean result is zero diffs,
    # not one per replacement
    if n_diff != 0:
        print("VERIFY FAILED - not installing")
        return 4

    entry_before = len(load_entry(ASAR))
    print("  entry size         : %d -> %d (%+d)" % (entry_before, len(text.encode("utf-8")), len(text.encode("utf-8")) - entry_before))

    print()
    install(built)
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description="Stage 7 launcher GameIPC routing")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--revert", action="store_true")
    args = parser.parse_args(argv)

    if args.apply:
        return cmd_apply(1, SITES, "splices")
    if args.revert:
        return cmd_apply(-1, reverse_spans(), "reverse splices")
    return report(load_entry(ASAR).decode("utf-8"))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
