"""Independent read-back of a Lunar app.asar.

Not asar_tool.py - that one takes no asar path argument and always reads a hardcoded
file, so every diagnostic run against it was actually looking at the live asar and
reporting on a different container than the one under test. This takes the path.

Reads straight from the byte array at the offset the header names, and checks the
signature of each patched entry rather than trusting the tree's size and offset fields
to be well-formed. A size that happens to match is not evidence that the right bytes
are behind it - three installs shipped a PNG while every structural check passed.
"""

import struct
import json
import sys

WANT_MODULE = b"// rat-accounts.js"
PROBE = b"buildChip"
BRIDGE = b"window.lunar.auth.addAccount"
HANDLER = b"if(t&&t.username)return this.addLocalAccount"
METHOD = b"async addLocalAccount(t){"
SCRIPT = b'<script src="../assets/rat-accounts.js"></script>'


def main():
    p = sys.argv[1]
    raw = open(p, "rb").read()

    u32 = [struct.unpack("<I", raw[i : i + 4])[0] for i in range(0, 16, 4)]
    jl = u32[3]
    tree = json.loads(raw[16 : 16 + jl].decode("utf-8"))
    # data_start comes from the block size, not from guessing an alignment: the header
    # runs byte-aligned to the data section, and the original container reports offsets
    # aligned to 1, so rounding up here would silently read the wrong bytes.
    ds = u32[1] + 8

    print("file   : %s" % p)
    print("size   : %d" % len(raw))
    print("u32    : %s   data_start %d" % (u32, ds))
    print()

    def walk(n, b=""):
        for k, v in n.get("files", {}).items():
            full = b + "/" + k
            if "files" in v:
                yield from walk(v, full)
            else:
                yield full, v

    def blob(path):
        for f, n in walk(tree):
            if f == path:
                o = ds + int(n["offset"])
                return raw[o : o + int(n["size"])]
        return None

    bad = []

    def check(label, path, needle):
        b = blob(path)
        if b is None:
            print("  %-10s MISSING entry  %s" % (label, path))
            bad.append(label)
            return
        ok = needle in b
        print(
            "  %-10s %-4s  %7d B   %s%s"
            % (label, "OK" if ok else "WRONG", len(b), b[:24].decode("utf-8", "replace").replace("\n", " "), "..." if len(b) > 24 else "")
        )
        if not ok:
            bad.append(label)

    print("entry checks")
    check("module", "/dist/assets/rat-accounts.js", WANT_MODULE)
    check("html", "/dist/html/main.html", SCRIPT)
    check("handler", "/dist-electron/electron/main.js", HANDLER)
    check("method", "/dist-electron/electron/main.js", METHOD)
    check("bridge", "/dist-electron/preload/launcher/index.js", b"addAccount(e){return await u.ipcRenderer.invoke")
    print()

    m = blob("/dist/assets/rat-accounts.js")
    if m:
        print("module detail")
        print("  probe   buildChip      : %s" % (PROBE in m))
        print("  bridge  window.lunar   : %s" % (BRIDGE in m))
        print("  chip    Add cracked    : %s" % (b"Add cracked account" in m))
        print("  first16 : %r" % m[:16])
        print()

    n = sum(1 for _, _ in walk(tree))
    print("entries : %d" % n)
    print()
    print("verdict : %s" % ("OK" if not bad else "FAILED -> " + ", ".join(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
