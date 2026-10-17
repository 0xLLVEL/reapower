using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

public class Cli {
    byte[] b;
    int[] secVA, secVSize, secRawPtr, secRawSize;
    int strBase;
    long valid;
    int[] rows = new int[64];
    int nTypeDef, nMethodDef;
    int tdStart, tdStride, mdStart, mdStride, mdNameOff;
    int tdrSize, fldIdxSize, mthIdxSize, prmIdxSize, blobIdxSize, strIdxSize, guidIdxSize, rsScopeSize;
    public List<string> Lines = new List<string>();
    int[] mdOff;
    int[] mdSize;
    int[] mdRowTok;
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
        mdOff = new int[nMethodDef]; mdSize = new int[nMethodDef]; mdRowTok = new int[nMethodDef];
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
            mdOff[r] = ilOff; mdSize[r] = ilSize; mdRowTok[r] = 0x06000000 + r + 1;
            int tIdx = typeOfRow[r + 1];
            Lines.Add(string.Format("0x06{0:X6}\t{1}\t{2}::{3}\t{4}\t{5}\t{6}",
                r + 1, r + 1, tnames[tIdx], nm, rva, ilSize, ilOff));
        }
    }

    public void Dump(string outPath) { File.WriteAllLines(outPath, Lines); }

    public string Describe(int row) {
        if (row < 1 || row > Lines.Count) return "?";
        string[] f = Lines[row - 1].Split('\t');
        return f[2] + " il=" + f[4] + " @off " + f[5];
    }

    public string FindRefs(int targetToken) {
        int row = targetToken & 0xFFFFFF;
        if (row < 1 || row > nMethodDef) return "  (token out of range)";
        byte t0 = (byte)(targetToken & 0xFF), t1 = (byte)((targetToken >> 8) & 0xFF),
             t2 = (byte)((targetToken >> 16) & 0xFF), t3 = (byte)((targetToken >> 24) & 0xFF);
        // sorted-by-ilOff index for binary search
        int[] idx = new int[nMethodDef];
        int n = 0;
        for (int k = 0; k < nMethodDef; k++) if (mdOff[k] >= 0) idx[n++] = k;
        Array.Sort(idx, (x, y) => mdOff[x].CompareTo(mdOff[y]));
        StringBuilder sb = new StringBuilder();
        int raw = 0, outside = 0;
        HashSet<int> callerRows = new HashSet<int>();
        List<string> detail = new List<string>();
        for (int i = 0; i + 4 < b.Length; i++) {
            if (b[i] == t0 && b[i + 1] == t1 && b[i + 2] == t2 && b[i + 3] == t3) {
                raw++;
                int lo = 0, hi = n - 1, found = -1;
                while (lo <= hi) {
                    int mid = (lo + hi) / 2;
                    int off = mdOff[idx[mid]];
                    if (i < off) hi = mid - 1;
                    else if (i >= off + mdSize[idx[mid]]) lo = mid + 1;
                    else { found = idx[mid]; break; }
                }
                if (found < 0) { outside++; continue; }
                callerRows.Add(found + 1);
                if (detail.Count < 200) {
                    byte op = i > 0 ? b[i - 1] : (byte)0;
                    detail.Add(string.Format("    op=0x{0:X2} off={1} caller={2} tok=0x06{3:X6}", op, i, Lines[found].Split('\t')[2], found + 1));
                }
            }
        }
        sb.AppendLine("  rawTokenHits=" + raw + "  outsideIL=" + outside + "  uniqueCallers=" + callerRows.Count);
        foreach (int c in callerRows) {
            string[] f = Lines[c - 1].Split('\t');
            sb.AppendLine("    [il@off " + f[5] + " il=" + f[4] + "] " + f[2] + "  tok=0x06" + c.ToString("X6"));
        }
        foreach (string d in detail) if (d.Contains("op=0x28") || d.Contains("op=0x6F") || d.Contains("op=0x73")) sb.AppendLine(d);
        return sb.ToString();
    }
    public string FindPattern(byte[] pat) {
        System.Text.StringBuilder sb = new System.Text.StringBuilder();
        for (int i = 0; i + pat.Length < b.Length; i++) {
            bool ok = true;
            for (int j = 0; j < pat.Length; j++) { if (b[i + j] != pat[j]) { ok = false; break; } }
            if (!ok) continue;
            int found = -1;
            for (int k = 0; k < nMethodDef; k++) {
                int off = mdOff[k], sz2 = mdSize[k];
                if (off >= 0 && i >= off && i < off + sz2) { found = k + 1; break; }
            }
            string where = found > 0 ? Lines[found - 1].Split('\t')[2] + "  tok=0x06" + found.ToString("X6") : "(not in IL)";
            byte prev = i > 0 ? b[i - 1] : (byte)0;
            sb.AppendLine("    off=" + i + " prevOp=0x" + prev.ToString("X2") + "  " + where);
        }
        return sb.ToString();
    }
}
