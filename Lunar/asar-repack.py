"""Read, rebuild and verify a Lunar app.asar.

The container was decoded empirically rather than assumed (first 16 bytes of the live
file: 04 00 00 00 74 4e 05 00 70 4e 05 00 6c 4e 05 00):

  [0:4]   uint32 = 4                 size of the following pickle
  [4:8]   uint32 = 347764            size of the header block starting at byte 8
  [8:12]  uint32 = 347760            json length + 4
  [12:16] uint32 = 347756            json string length
  [16:]   JSON, padded to 4-byte alignment
  data    embedded files, concatenated in tree order

Each embedded entry carries a size and an offset relative to the data section. Packing
aligns those offsets, which `inspect` measures from the original rather than assuming.

`replace` is the reason this file exists: an edit that changes a file's length moves
everything packed after it, so every offset from that point on has to be recomputed and
the header rewritten. `verify` then proves the rebuild was lossless by comparing every
embedded file, byte for byte, against the original.
"""

import struct
import json
import sys
import os

ASAR = r"C:\Users\ezan\AppData\Local\Programs\Lunar Client\resources\app.asar"


def read_container(path):
    with open(path, "rb") as f:
        head = f.read(16)
        if struct.unpack("<I", head[0:4])[0] != 4:
            raise SystemExit("not an asar: first uint32 is not 4")
        block = struct.unpack("<I", head[4:8])[0]
        json_len = struct.unpack("<I", head[12:16])[0]
        raw = f.read(json_len)
        tree = json.loads(raw.decode("utf-8"))
        data_start = 16 + json_len
        data_start += (-data_start) % 4
    return tree, data_start, json_len, block


def walk(node, base=""):
    """Yield (path, entry, parents) in document order."""
    for name, child in node.get("files", {}).items():
        full = base + "/" + name
        if "files" in child:
            for item in walk(child, full):
                yield item
        else:
            yield full, child, node


def inspect(path):
    tree, data_start, json_len, block = read_container(path)
    entries = list(walk(tree))

    embedded = [(p, n) for p, n, _ in entries if not n.get("unpacked")]
    unpacked = [(p, n) for p, n, _ in entries if n.get("unpacked")]

    # measure the alignment the original builder used
    offsets = sorted(int(n["offset"]) for _, n in embedded)
    sizes = {int(n["offset"]): int(n["size"]) for _, n in embedded}
    gaps = []
    for off in offsets[:-1]:
        end = off + sizes[off]
        nxt = offsets[offsets.index(off) + 1]
        gaps.append(nxt - end)
    align = 0
    for g in (1, 2, 4, 8):
        if all(x % g == 0 for x in offsets):
            align = g

    total = max(int(n["offset"]) + int(n["size"]) for _, n in embedded)

    out = []
    out.append("data_start   : %d" % data_start)
    out.append("json_len     : %d   header_block %d" % (json_len, block))
    out.append("entries      : %d   embedded %d, unpacked %d" % (len(entries), len(embedded), len(unpacked)))
    out.append("offset align : %d bytes" % align)
    out.append("min gap      : %d   max gap %d   zero-gaps %d" % (min(gaps), max(gaps), sum(1 for g in gaps if g == 0)))
    out.append("data span    : %d   file %d   trailing %d" % (total, os.path.getsize(path), os.path.getsize(path) - data_start - total))

    # confirm every offset/size reads back as a real file
    bad = []
    with open(path, "rb") as f:
        for p, n in embedded:
            f.seek(data_start + int(n["offset"]))
            blob = f.read(int(n["size"]))
            if len(blob) != int(n["size"]):
                bad.append((p, "short read"))
    out.append("read check   : %s (%d bad)" % ("OK" if not bad else "FAIL", len(bad)))
    for p, why in bad[:10]:
        out.append("  BAD %s %s" % (p, why))
    return "\n".join(out)


def repack(src, dst, entry_path, new_bytes, align=4):
    """Rebuild the asar with one embedded file replaced, preserving tree order."""
    tree, _, _, _ = read_container(src)

    with open(src, "rb") as f:
        original = f.read()

    _, data_start, _, _ = read_container(src)

    # collect embedded files in tree order, swapping in the replacement
    chunks = []
    touched = None

    def visit(node, base=""):
        nonlocal touched
        for name, child in node.get("files", {}).items():
            full = base + "/" + name
            if "files" in child:
                visit(child, full)
                continue
            if child.get("unpacked"):
                continue
            if full == entry_path:
                child["size"] = len(new_bytes)
                touched = full
                chunks.append(new_bytes)
            else:
                start = data_start + int(child["offset"])
                chunks.append(original[start : start + int(child["size"])])

    visit(tree)

    if touched is None:
        raise SystemExit("entry not found in asar: %s" % entry_path)

    # reassign offsets in the same order, padding each file to the alignment
    cursor = 0
    padded = []

    def assign(node, base=""):
        nonlocal cursor
        for name, child in node.get("files", {}).items():
            full = base + "/" + name
            if "files" in child:
                assign(child, full)
                continue
            if child.get("unpacked"):
                continue
            child["offset"] = str(cursor)
            cursor += int(child["size"])
            pad = (-cursor) % align
            cursor += pad

    assign(tree)

    # rebuild the data section with the original padding preserved
    data = bytearray()
    ci = 0

    def emit(node, base=""):
        nonlocal ci
        for name, child in node.get("files", {}).items():
            full = base + "/" + name
            if "files" in child:
                emit(child, full)
                continue
            if child.get("unpacked"):
                continue
            data.extend(chunks[ci])
            ci += 1
            pad = (-len(data)) % align
            data.extend(b"\0" * pad)

    emit(tree)

    header = json.dumps(tree, separators=(",", ":")).encode("utf-8")
    pad = (-(16 + len(header))) % align
    header += b"\0" * pad

    body = bytearray()
    body += struct.pack("<I", 4)
    body += struct.pack("<I", 4 + 4 + len(header))
    body += struct.pack("<I", len(header) + 4)
    body += struct.pack("<I", len(header))
    body += header
    body += data

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(body)
    return touched, len(body), len(data)


def verify(original_path, rebuilt_path):
    """Every embedded file must be byte-identical except the one we replaced."""
    t1, d1, _, _ = read_container(original_path)
    t2, d2, _, _ = read_container(rebuilt_path)

    with open(original_path, "rb") as f1, open(rebuilt_path, "rb") as f2:
        e1 = {p: n for p, n, _ in walk(t1) if not n.get("unpacked")}
        e2 = {p: n for p, n, _ in walk(t2) if not n.get("unpacked")}

        missing = set(e1) - set(e2)
        added = set(e2) - set(e1)
        diffs = []
        for p in sorted(set(e1) & set(e2)):
            f1.seek(d1 + int(e1[p]["offset"]))
            f2.seek(d2 + int(e2[p]["offset"]))
            b1 = f1.read(int(e1[p]["size"]))
            b2 = f2.read(int(e2[p]["size"]))
            if b1 != b2:
                diffs.append((p, len(b1), len(b2)))

    out = []
    out.append("missing entries : %d" % len(missing))
    out.append("added entries   : %d" % len(added))
    out.append("byte-different  : %d" % len(diffs))
    for p, a, b in diffs:
        out.append("  DIFF %-46s %d -> %d" % (p, a, b))
    out.append("verdict         : %s" % ("OK" if not missing and not added and len(diffs) == 1 else "CHECK"))
    return "\n".join(out)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "inspect"

    if cmd == "inspect":
        print(inspect(sys.argv[2] if len(sys.argv) > 2 else ASAR))

    elif cmd == "replace":
        src, dst, entry, newfile = sys.argv[2:6]
        with open(newfile, "rb") as f:
            nb = f.read()
        touched, total, datalen = repack(src, dst, entry, nb)
        print("replaced : %s" % touched)
        print("new size : %d   data %d" % (total, datalen))
        print()
        print(verify(src, dst))

    elif cmd == "verify":
        print(verify(sys.argv[2], sys.argv[3]))

    else:
        print("unknown cmd:", cmd)


if __name__ == "__main__":
    main()
