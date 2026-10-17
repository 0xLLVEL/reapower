"use strict";
/*
 * herd-pro / bake_reference.cjs — the reference implementation of the asar
 * rewrite, in node. HerdPatch.ps1 is the shipped engine; this exists so the
 * PowerShell one can be checked against something small enough to read in one
 * sitting, and so the byte layout is written down twice in two languages.
 *
 * Both must produce an archive whose data region is byte-identical to the
 * original and whose header differs only in the target entry. Cross-check with
 * tools/compare_asar.ps1.
 *
 * ASAR layout:
 *   [u32 4][u32 headerPickleSize][u32 headerPicklePayload][u32 jsonLen][json .. <=3 pad][data ..]
 *
 * A file entry's `offset` is relative to the START OF THE DATA REGION, not to
 * the file. So when the header grows or shrinks, the data region slides by
 * `delta` and every existing entry keeps its offset untouched — only the
 * appended replacement needs one, and that is simply `oldDataSize`.
 *
 * No other byte in the archive moves or changes.
 *
 * usage:
 *   node bake_reference.cjs --asar <path> --src <loader.js> --append <shim.js>
 *                           [--out <path>] [--target out/main/index.js]
 */

const fs = require("fs");
const path = require("path");

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const ASAR = arg("asar");
const SRC = arg("src");
const APPEND = arg("append");
const OUT = arg("out", ASAR);
const TARGET = arg("target", "out/main/index.js");

if (!ASAR || !SRC || !APPEND) {
  console.error("usage: node bake_reference.cjs --asar <path> --src <loader.js> --append <shim.js> [--out <path>] [--target <entry>]");
  process.exit(2);
}

function readHeader(file) {
  const fd = fs.openSync(file, "r");
  try {
    const sizeBuf = Buffer.alloc(8);
    fs.readSync(fd, sizeBuf, 0, 8, 0);
    const headerSize = sizeBuf.readUInt32LE(4);
    const headerBuf = Buffer.alloc(headerSize);
    fs.readSync(fd, headerBuf, 0, headerSize, 8);
    const jsonLen = headerBuf.readUInt32LE(4);
    return {
      tree: JSON.parse(headerBuf.toString("utf8", 8, 8 + jsonLen)),
      jsonLen,
      headerSize,
      dataStart: 8 + headerSize,
    };
  } finally {
    fs.closeSync(fd);
  }
}

function findEntry(tree, relPath) {
  let node = tree;
  for (const part of relPath.split("/").filter(Boolean)) {
    if (!node.files || !node.files[part]) return null;
    node = node.files[part];
  }
  return node;
}

function main() {
  const { tree, jsonLen, dataStart } = readHeader(ASAR);
  const oldFileSize = fs.statSync(ASAR).size;
  const oldDataSize = oldFileSize - dataStart;

  const entry = findEntry(tree, TARGET);
  if (!entry || entry.files) throw new Error(`target entry not found: ${TARGET}`);
  if (entry.unpacked) throw new Error(`target entry is unpacked, cannot bake: ${TARGET}`);

  const payload = Buffer.concat([
    fs.readFileSync(SRC),
    Buffer.from("\n/* ---- herd-pro ---- */\n", "utf8"),
    fs.readFileSync(APPEND),
    Buffer.from("\n/* ---- /herd-pro ---- */\n", "utf8"),
  ]);

  // content changed on purpose, so the shipped digest no longer applies
  delete entry.integrity;
  entry.size = payload.length;
  entry.offset = String(oldDataSize);

  const jsonBytes = Buffer.from(JSON.stringify(tree), "utf8");
  const pad = (4 - (jsonBytes.length % 4)) % 4;
  const newHeaderSize = 8 + jsonBytes.length + pad;
  const newDataStart = 8 + newHeaderSize;

  // [0]  size-pickle payload length (always 4)
  // [4]  size-pickle value = length of the header pickle buffer
  // [8]  header-pickle payload length = buffer length - 4  <- Electron rejects
  //      the archive outright (and silently) if this one is wrong
  // [12] header-pickle string length
  // [16] header JSON
  const header = Buffer.alloc(newDataStart);
  header.writeUInt32LE(4, 0);
  header.writeUInt32LE(newHeaderSize, 4);
  header.writeUInt32LE(newHeaderSize - 4, 8);
  header.writeUInt32LE(jsonBytes.length, 12);
  jsonBytes.copy(header, 16);

  const tmp = path.join(path.dirname(path.resolve(OUT)), `.${path.basename(OUT)}.herd-pro.tmp`);
  const inFd = fs.openSync(ASAR, "r");
  const outFd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(outFd, header, 0, header.length, 0);

    const CHUNK = 8 * 1024 * 1024;
    const buf = Buffer.alloc(CHUNK);
    let remaining = oldDataSize;
    let srcPos = dataStart;
    let dstPos = newDataStart;
    while (remaining > 0) {
      const n = Math.min(CHUNK, remaining);
      fs.readSync(inFd, buf, 0, n, srcPos);
      fs.writeSync(outFd, buf, 0, n, dstPos);
      srcPos += n;
      dstPos += n;
      remaining -= n;
    }
    fs.writeSync(outFd, payload, 0, payload.length, newDataStart + oldDataSize);
    fs.ftruncateSync(outFd, newDataStart + oldDataSize + payload.length);
  } finally {
    fs.closeSync(inFd);
    fs.closeSync(outFd);
  }
  fs.renameSync(tmp, OUT);

  console.log(JSON.stringify({
    target: TARGET,
    oldDataStart: dataStart,
    newDataStart,
    headerGrowth: newDataStart - dataStart,
    oldFileSize,
    newFileSize: newDataStart + oldDataSize + payload.length,
    payloadBytes: payload.length,
  }, null, 1));
}

main();
