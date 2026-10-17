using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Durable PE + CLI metadata reader: used to locate a MethodDef by full name,
// verify its current IL via SHA-256, then overwrite the method body in place
// without touching the metadata tables.
public class TPCli {
    byte[] b;
    int[] secVA, secVSize, secRawPtr, secRawSize;
    int strBase;
    long valid;
    int[] rows = new int[64];
    int nTypeDef, nMethodDef;
    int tdStart, tdStride, mdStart, mdStride, mdNameOff;
    int tdrSize, fldIdxSize, mthIdxSize, prmIdxSize, blobIdxSize, strIdxSize, guidIdxSize, rsScopeSize;
    int[] mdOff;
    int[] mdSize;
    int[] mdRva;
    string[] mdName;
    public List<string> Lines = new List<string>();
    public int Count { get { return nMethodDef; } }

    static int U16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }
    static int U32(byte[] b, int o) { return (int)BitConverter.ToUInt32(b, o); }

    int Rva2Off(int rva) {
        for (int i = 0; i < secVA.Length; i++) {
            int vs = Math.Max(secVSize[i], secRawSize[i]);
            if (rva >= secVA[i] && rva < secVA[i] + vs) return rva - secVA[i] + secRawPtr[i];
        }
        return -1;
    }

    string Str(int idx) {
        if (idx == 0) return "";
        int q = strBase + idx;
        StringBuilder sb = new StringBuilder();
        while (b[q] != 0) { sb.Append((char)b[q]); q++; }
        return sb.ToString();
    }

    static int Coded(int[] counts, int bits) {
        int m = 0; foreach (int c in counts) if (c > m) m = c;
        return m < (1 << (16 - bits)) ? 2 : 4;
    }

    public void Load(string path) {
        b = File.ReadAllBytes(path);
        int pe = U32(b, 0x3C);
        int coff = pe + 4;
        int numSec = U16(b, coff + 2);
        int optSize = U16(b, coff + 16);
        int optOff = coff + 20;
        bool is64 = U16(b, optOff) == 0x20B;
        int secTab = optOff + optSize;
        int dirBase = is64 ? optOff + 112 : optOff + 96;
        secVA = new int[numSec]; secVSize = new int[numSec]; secRawPtr = new int[numSec]; secRawSize = new int[numSec];
        for (int i = 0; i < numSec; i++) {
            int s = secTab + i * 40;
            secVSize[i] = U32(b, s + 8); secVA[i] = U32(b, s + 12);
            secRawSize[i] = U32(b, s + 16); secRawPtr[i] = U32(b, s + 20);
        }
        int cliOff = Rva2Off(U32(b, dirBase + 14 * 8));
        int root = Rva2Off(U32(b, cliOff + 8));
        int verLen = U32(b, root + 12);
        int p = root + 16 + verLen + 2;
        int nsCount = U16(b, p); p += 2;
        int tOff = -1;
        for (int i = 0; i < nsCount; i++) {
            int soff = U32(b, p); p += 8;
            StringBuilder sb = new StringBuilder();
            while (b[p] != 0) { sb.Append((char)b[p]); p++; }
            p++; p = (p + 3) / 4 * 4;
            if (sb.ToString() == "#Strings") strBase = root + soff;
            if (sb.ToString() == "#~") tOff = root + soff;
        }
        int t = tOff;
        int hs = b[t + 6];
        strIdxSize = (hs & 1) != 0 ? 4 : 2;
        guidIdxSize = (hs & 2) != 0 ? 4 : 2;
        blobIdxSize = (hs & 4) != 0 ? 4 : 2;
        valid = BitConverter.ToInt64(b, t + 8);
        int tp = t + 24;
        for (int i = 0; i < 64; i++) { if ((valid & (1L << i)) != 0) { rows[i] = U32(b, tp); tp += 4; } else rows[i] = 0; }
        Func<int, int> sz = c => c >= 65536 ? 4 : 2;
        rsScopeSize = Coded(new int[]{ rows[0], rows[0x1A], rows[0x23], rows[1] }, 2);
        tdrSize = Coded(new int[]{ rows[2], rows[1], rows[0x1B] }, 2);
        fldIdxSize = sz(rows[4]); mthIdxSize = sz(rows[6]); prmIdxSize = sz(rows[8]);
        int rs00 = 2 + strIdxSize + 3 * guidIdxSize;
        int rs01 = rsScopeSize + 2 * strIdxSize;
        int rs02 = 4 + 2 * strIdxSize + tdrSize + fldIdxSize + mthIdxSize;
        int rs03 = fldIdxSize;
        int rs04 = 2 + strIdxSize + blobIdxSize;
        int rs05 = mthIdxSize;
        tdStride = rs02;
        mdStride = 4 + 2 + 2 + strIdxSize + blobIdxSize + prmIdxSize;
        nTypeDef = rows[2]; nMethodDef = rows[6];
        tdStart = tp + rs00 * rows[0] + rs01 * rows[1];
        mdStart = tdStart + rs02 * nTypeDef + rs03 * rows[3] + rs04 * rows[4] + rs05 * rows[5];
        mdNameOff = 8;
        int[] firstM = new int[nTypeDef + 1];
        string[] tnames = new string[nTypeDef];
        for (int r = 0; r < nTypeDef; r++) {
            int rp = tdStart + r * tdStride;
            int nIdx = strIdxSize == 4 ? U32(b, rp + 4) : U16(b, rp + 4);
            int nsIdx = strIdxSize == 4 ? U32(b, rp + 4 + strIdxSize) : U16(b, rp + 4 + strIdxSize);
            int mlo = rp + 4 + 2 * strIdxSize + tdrSize + fldIdxSize;
            int mlv = mthIdxSize == 4 ? U32(b, mlo) : U16(b, mlo);
            string ns = Str(nsIdx), nm = Str(nIdx);
            tnames[r] = ns.Length > 0 ? ns + "." + nm : nm;
            firstM[r] = mlv;
        }
        int[] order = new int[nTypeDef];
        for (int i = 0; i < nTypeDef; i++) order[i] = i;
        Array.Sort(order, (x, y) => firstM[x].CompareTo(firstM[y]));
        mdOff = new int[nMethodDef]; mdSize = new int[nMethodDef];
        mdRva = new int[nMethodDef]; mdName = new string[nMethodDef];
        int[] typeOfRow = new int[nMethodDef + 2];
        for (int i = 0; i < nTypeDef; i++) {
            int lo = firstM[order[i]];
            int hi = (i + 1 < nTypeDef) ? firstM[order[i + 1]] : nMethodDef + 1;
            for (int m = lo; m < hi && m <= nMethodDef; m++) typeOfRow[m] = order[i];
        }
        for (int r = 0; r < nMethodDef; r++) {
            int rp = mdStart + r * mdStride;
            int rva = U32(b, rp);
            int nIdx = strIdxSize == 4 ? U32(b, rp + mdNameOff) : U16(b, rp + mdNameOff);
            string nm = Str(nIdx);
            int ilOff = -1, ilSize = -1;
            if (rva != 0) {
                int o = Rva2Off(rva);
                if (o >= 0) {
                    int hdr = b[o]; int fmt = hdr & 3;
                    if (fmt == 2) { ilSize = hdr >> 2; ilOff = o + 1; }
                    else if (fmt == 3) { ilSize = U32(b, o + 4); ilOff = o + 12; }
                }
            }
            mdOff[r] = ilOff; mdSize[r] = ilSize; mdRva[r] = rva; mdName[r] = nm;
            int tIdx = typeOfRow[r + 1];
            Lines.Add(string.Format("0x06{0:X6}\t{1}\t{2}::{3}\t{4}\t{5}\t{6}",
                r + 1, r + 1, tnames[tIdx], nm, rva, ilSize, ilOff));
        }
    }

    public byte[] Bytes { get { return b; } }
    public int FindRow(string fullName) {
        for (int r = 0; r < nMethodDef; r++) {
            string[] f = Lines[r].Split('\t');
            if (f[2] == fullName) return r + 1;
        }
        return -1;
    }
    public string NameOf(int row) {        string[] f = Lines[row - 1].Split('\t');
        return f[2];
    }
    public string SimpleNameOf(int row) {
        string n = NameOf(row);
        int i = n.LastIndexOf("::");
        return i < 0 ? n : n.Substring(i + 2);
    }
    // every MethodDef sharing the same short name (used as a safety net in case
    // TablePlus one day tidies up or moves the declaring type)
    public int[] FindRowsByName(string simpleName) {
        List<int> hit = new List<int>();
        for (int r = 0; r < nMethodDef; r++) if (SimpleNameOf(r + 1) == simpleName) hit.Add(r + 1);
        return hit.ToArray();
    }

    public int IlStart(int row) { return mdOff[row - 1]; }
    public int IlSize(int row) { return mdSize[row - 1]; }
    public int BodyStart(int row) { return mdOff[row - 1] - 1; }
    public int Rva(int row) { return mdRva[row - 1]; }

    public byte[] IlBytes(int row) {
        int off = mdOff[row - 1], n = mdSize[row - 1];
        byte[] il = new byte[n];
        Array.Copy(b, off, il, 0, n);
        return il;
    }

    public string IlSha(int row) {
        int off = mdOff[row - 1], n = mdSize[row - 1];
        byte[] il = new byte[n];
        Array.Copy(b, off, il, 0, n);
        using (SHA256 s = SHA256.Create()) return BitConverter.ToString(s.ComputeHash(il)).Replace("-", "").ToLowerInvariant();
    }

    public string IlHex(int row) {
        int off = mdOff[row - 1], n = mdSize[row - 1];
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.Append(b[off + i].ToString("X2"));
        return sb.ToString();
    }

    // Only TINY bodies are replaced. Capacity = original IL size; surplus bytes are zero-filled.
    public bool PatchIl(int row, byte[] newIl) {
        int r = row - 1;
        int off = mdOff[r], cap = mdSize[r];
        if (off < 0 || cap < 0) return false;
        if ((b[off - 1] & 3) != 2) return false;
        if (newIl.Length > cap) return false;
        b[off - 1] = (byte)((newIl.Length << 2) | 2);
        Array.Copy(newIl, 0, b, off, newIl.Length);
        for (int i = newIl.Length; i < cap; i++) b[off + i] = 0x00;
        mdSize[r] = newIl.Length;
        return true;
    }

    public void Save(string path) { File.WriteAllBytes(path, b); }
}
