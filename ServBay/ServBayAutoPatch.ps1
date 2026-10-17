<#
  ServBayAutoPatch.ps1
  ------------------------------------------------------------------
  ServBay entitlement unlock -- self-locating, version-agnostic.

  Why this exists
    The first patchers hard-coded file offsets. Every ServBay update
    moves those offsets, so the patch silently stops working (or worse,
    corrupts an unrelated method). This script REDISCOVERS everything
    from the new binary:

      * gate methods        -> found by metadata name (TypeDef::Method)
      * obfuscated blob     -> base found by FieldRVA ldtoken + scan
      * string cipher       -> derived from the <PrivateImplementationDetails>
                               .cctor IL (constants + op shape), verified by
                               decoding until the target text appears
      * plan label          -> found inside the DECODED blob, rewritten in place

    Nothing is hard-coded except the semantic names of the 7 gates and the
    label strings. If ServBay renames a gate, the log says not-found instead
    of patching the wrong thing.

  Idempotent
    "changes == 0" means the binary is already patched. Safe to run forever.

  Usage
    .\ServBayAutoPatch.ps1 -DryRun          # report only, writes nothing
    .\ServBayAutoPatch.ps1                  # patch (stops+restarts ServBay)
    .\ServBayAutoPatch.ps1 -NoRestart       # patch, leave ServBay stopped
#>
[CmdletBinding()]
param(
    [string]$Dll       = "C:\ServBay\app\ServBay.dll",
    [string]$StateDir  = "C:\ProgramData\ServBayPatch",
    [string]$FromText  = "ServBay Free",
    [string]$ToText    = "ServBay Pro ",
    [switch]$DryRun,
    [switch]$NoRestart,
    [switch]$NoStop,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$LogPath   = Join-Path $StateDir 'autopatch.log'
$StatePath = Join-Path $StateDir 'state.json'
$BackupDir = Join-Path $StateDir 'backup'

function Write-Log([string]$msg, [string]$level = 'INFO') {
    $line = ('{0}  {1,-5}  {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $level, $msg)
    if (-not $Quiet) { Write-Host $line }
    if (Test-Path $StateDir) {
        try {
            Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
            if ((Get-Item -LiteralPath $LogPath).Length -gt 2MB) {
                $tail = Get-Content -LiteralPath $LogPath -Tail 2000
                Set-Content -LiteralPath $LogPath -Value $tail -Encoding UTF8
            }
        } catch { }
    }
}

function Get-ServBayProcesses {
    Get-CimInstance Win32_Process -Filter "Name LIKE 'ServBay%'" -ErrorAction SilentlyContinue
}

function Stop-ServBay {
    $procs = @(Get-ServBayProcesses)
    foreach ($p in $procs) {
        try { $p | Invoke-CimMethod -MethodName Terminate | Out-Null; Write-Log ("terminated pid {0} ({1})" -f $p.ProcessId, $p.Name) }
        catch { Write-Log ("could not terminate pid {0}: {1}" -f $p.ProcessId, $_.Exception.Message) 'WARN' }
    }
    for ($i = 0; $i -lt 20; $i++) {
        if (@(Get-ServBayProcesses).Count -eq 0) { break }
        Start-Sleep -Milliseconds 500
    }
    return ($procs.Count -gt 0)
}

function Start-ServBay {
    $exe = Join-Path (Split-Path $Dll -Parent) 'ServBay.exe'
    if (-not (Test-Path -LiteralPath $exe)) { Write-Log "ServBay.exe not found at $exe" 'WARN'; return }
    try {
        Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe -Parent) | Out-Null
        Write-Log "restarted ServBay"
    } catch { Write-Log ("restart failed: " + $_.Exception.Message) 'WARN' }
}

# ---------------------------------------------------------------------------
# C# engine: metadata walk + name lookup + blob crack + in-place patch
# ---------------------------------------------------------------------------
$cs = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

public class SBP
{
    public static readonly string[] GateNames = new string[] {
        "ServBay.Services.Entitlement.EntitlementStore::IsVipEntitled",
        "ServBay.Services.Entitlement.EntitlementService::IsEntitledVip",
        "ServBay.Services.Entitlement.EntitlementService::IsPaidEntitlement",
        "ServBay.Services.Entitlement.LicenseVerifier::Verify",
        "ServBay.Services.Entitlement.EntitlementCredentialVerdict::Verdict",
        "ServBay.Services.Entitlement.BridgeVIPGate::ShouldBlock",
        "ServBay.Services.AiGatewayVipOnlyEndpoints::RequiresVip"
    };
    public static readonly int[]  GateValues = new int[]  { 1, 1, 1, 1, 3, 0, 0 };
    public static readonly bool[] GateIsBool = new bool[] { true, true, true, true, false, false, false };

    public class Meth {
        public int Row, Rva, HdrOff, IlOff, IlSize, Fmt;
        public string Type, Name;
        public string Full  { get { return Type + "::" + Name; } }
        public string Token { get { return "0x06" + Row.ToString("X6"); } }
    }

    class Cipher {
        public string Name; public bool Xor; public int C1, Mode;
    }

    byte[] b;
    int[] sVA, sVS, sRP, sRS;
    int strBase, blobBase;
    int strIdxSize, guidIdxSize, blobIdxSize;
    int[] rows = new int[64];
    int nTypeDef, nMethodDef, tdStart, tdStride, mdStart, mdStride;
    public List<Meth> Methods = new List<Meth>();

    static int U16(byte[] x, int o) { return BitConverter.ToUInt16(x, o); }
    static int U32(byte[] x, int o) { return (int)BitConverter.ToUInt32(x, o); }
    static int Coded(int[] counts, int bits) { int m = 0; foreach (int c in counts) if (c > m) m = c; return m < (1 << (16 - bits)) ? 2 : 4; }
    static string Hex(int[] a) { StringBuilder s = new StringBuilder(); for (int i = 0; i < a.Length; i++) { if (i > 0) s.Append(' '); s.Append(a[i].ToString("X2")); } return s.ToString(); }

    int Rva2Off(int rva) {
        for (int i = 0; i < sVA.Length; i++) {
            int vs = Math.Max(sVS[i], sRS[i]);
            if (rva >= sVA[i] && rva < sVA[i] + vs) return rva - sVA[i] + sRP[i];
        }
        return -1;
    }

    string Str(int idx) {
        if (idx == 0) return "";
        int q = strBase + idx;
        StringBuilder sb = new StringBuilder();
        while (q < b.Length && b[q] != 0) { sb.Append((char)b[q]); q++; }
        return sb.ToString();
    }

    static int Compressed(byte[] x, int o, out int size) {
        byte b0 = x[o];
        if ((b0 & 0x80) == 0) { size = 1; return b0; }
        if ((b0 & 0xC0) == 0x80) { size = 2; return ((b0 & 0x3F) << 8) | x[o + 1]; }
        size = 4;
        return ((b0 & 0x1F) << 24) | (x[o + 1] << 16) | (x[o + 2] << 8) | x[o + 3];
    }

    // ---------------- load / parse ----------------
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
        sVA = new int[numSec]; sVS = new int[numSec]; sRP = new int[numSec]; sRS = new int[numSec];
        for (int i = 0; i < numSec; i++) {
            int s = secTab + i * 40;
            sVS[i] = U32(b, s + 8); sVA[i] = U32(b, s + 12);
            sRS[i] = U32(b, s + 16); sRP[i] = U32(b, s + 20);
        }
        int cliOff = Rva2Off(U32(b, dirBase + 14 * 8));
        if (cliOff < 0) throw new Exception("no CLI header");
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
            string nm = sb.ToString();
            if (nm == "#Strings") strBase  = root + soff;
            if (nm == "#Blob")    blobBase = root + soff;
            if (nm == "#~")       tOff     = root + soff;
        }
        if (tOff < 0) throw new Exception("no #~ stream");

        int t = tOff;
        int hs = b[t + 6];
        strIdxSize  = (hs & 1) != 0 ? 4 : 2;
        guidIdxSize = (hs & 2) != 0 ? 4 : 2;
        blobIdxSize = (hs & 4) != 0 ? 4 : 2;
        long valid = BitConverter.ToInt64(b, t + 8);
        int tp = t + 24;
        for (int i = 0; i < 64; i++) { if ((valid & (1L << i)) != 0) { rows[i] = U32(b, tp); tp += 4; } else rows[i] = 0; }

        int rsScopeSize = Coded(new int[] { rows[0], rows[0x1A], rows[0x23], rows[1] }, 2);
        int tdrSize     = Coded(new int[] { rows[2], rows[1], rows[0x1B] }, 2);
        int fldIdxSize  = rows[4] >= 65536 ? 4 : 2;
        int mthIdxSize  = rows[6] >= 65536 ? 4 : 2;
        int prmIdxSize  = rows[8] >= 65536 ? 4 : 2;

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

        int[] firstM = new int[nTypeDef + 1];
        string[] tnames = new string[nTypeDef];
        for (int r = 0; r < nTypeDef; r++) {
            int rp = tdStart + r * tdStride;
            int nIdx  = strIdxSize == 4 ? U32(b, rp + 4) : U16(b, rp + 4);
            int nsIdx = strIdxSize == 4 ? U32(b, rp + 4 + strIdxSize) : U16(b, rp + 4 + strIdxSize);
            int mlo = rp + 4 + 2 * strIdxSize + tdrSize + fldIdxSize;
            int mlv = mthIdxSize == 4 ? U32(b, mlo) : U16(b, mlo);
            string ns = Str(nsIdx), nm = Str(nIdx);
            tnames[r] = ns.Length > 0 ? ns + "." + nm : nm;
            firstM[r] = mlv;
        }
        int[] order = new int[nTypeDef];
        for (int i = 0; i < nTypeDef; i++) order[i] = i;
        Array.Sort(order, delegate(int x, int y) { return firstM[x].CompareTo(firstM[y]); });
        int[] typeOfRow = new int[nMethodDef + 2];
        for (int i = 0; i < nTypeDef; i++) {
            int lo = firstM[order[i]];
            int hi = (i + 1 < nTypeDef) ? firstM[order[i + 1]] : nMethodDef + 1;
            for (int m = lo; m < hi && m <= nMethodDef; m++) typeOfRow[m] = order[i];
        }
        for (int r = 0; r < nMethodDef; r++) {
            int rp = mdStart + r * mdStride;
            int rva = U32(b, rp);
            int nIdx = strIdxSize == 4 ? U32(b, rp + 8) : U16(b, rp + 8);
            Meth m = new Meth();
            m.Row = r + 1; m.Rva = rva;
            m.Type = tnames[typeOfRow[r + 1]];
            m.Name = Str(nIdx);
            m.HdrOff = -1; m.IlOff = -1; m.IlSize = 0; m.Fmt = 0;
            if (rva != 0) {
                int o = Rva2Off(rva);
                if (o >= 0) {
                    int hdr = b[o]; int fmt = hdr & 3;
                    m.HdrOff = o; m.Fmt = fmt;
                    if (fmt == 2) { m.IlSize = hdr >> 2; m.IlOff = o + 1; }
                    else if (fmt == 3) { m.IlSize = U32(b, o + 4); m.IlOff = o + 12; }
                }
            }
            Methods.Add(m);
        }
    }

    public List<Meth> Find(string full) {
        List<Meth> res = new List<Meth>();
        for (int i = 0; i < Methods.Count; i++) if (Methods[i].Full == full) res.Add(Methods[i]);
        return res;
    }

    public string SigReturn(Meth m) {
        try {
            int rp = mdStart + (m.Row - 1) * mdStride + 8 + strIdxSize;
            int bi = blobIdxSize == 4 ? U32(b, rp) : U16(b, rp);
            int q = blobBase + bi;
            int sz; Compressed(b, q, out sz);
            int p2 = q + sz + 1;
            int psz; Compressed(b, p2, out psz); p2 += psz;
            byte rt = b[p2];
            switch (rt) {
                case 0x01: return "void";
                case 0x02: return "bool";
                case 0x08: return "int32";
                case 0x09: return "uint32";
                case 0x0E: return "string";
                case 0x11: return "valuetype";
                case 0x12: return "class";
            }
            return "etype0x" + rt.ToString("X2");
        } catch { return "?"; }
    }

    public static int[] WantStub(int v) {
        if (v >= 0 && v <= 8) return new int[] { 0x16 + v, 0x2A };
        return new int[] { 0x1F, v, 0x2A };
    }

    public void WriteBody(Meth m, int[] stub) {
        b[m.HdrOff] = (byte)((stub.Length << 2) | 0x02);
        for (int i = 0; i < stub.Length; i++) b[m.HdrOff + 1 + i] = (byte)stub[i];
    }

    public void Save(string path) { File.WriteAllBytes(path, b); }
    public int Length { get { return b.Length; } }

    static int IndexOf(byte[] hay, byte[] needle, int from) {
        int n = hay.Length - needle.Length;
        for (int i = from; i <= n; i++) {
            bool ok = true;
            for (int k = 0; k < needle.Length; k++) if (hay[i + k] != needle[k]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    // ---------------- blob crack ----------------
    static int KeyByte(int mode, int c1, int i) {
        switch (mode) {
            case 0: return (i ^ c1) & 0xFF;
            case 1: return (i + c1) & 0xFF;
            case 2: return (i - c1) & 0xFF;
            case 6: return 0;
        }
        return 0;
    }

    static byte Dec(int mode, int c1, byte raw, int i) {
        switch (mode) {
            case 0: return (byte)(raw ^ ((i ^ c1) & 0xFF));
            case 1: return (byte)(raw ^ ((i + c1) & 0xFF));
            case 2: return (byte)(raw ^ ((i - c1) & 0xFF));
            case 4: return (byte)((raw + ((i ^ c1) & 0xFF)) & 0xFF);
            case 5: return (byte)((raw - ((i ^ c1) & 0xFF)) & 0xFF);
            case 6: return raw;
        }
        return raw;
    }

    public bool DiscoverBlob(byte[] fromB, out int baseS, out string cname, out bool xorOk,
                             out int c1, out int cmode, out byte[] plain, out string err) {
        baseS = -1; cname = ""; xorOk = false; c1 = 0; cmode = 0; plain = null; err = "";

        Meth cc = null;
        for (int i = 0; i < Methods.Count; i++)
            if (Methods[i].Name == ".cctor" && Methods[i].Type.IndexOf("PrivateImplementationDetails") >= 0) { cc = Methods[i]; break; }
        if (cc == null || cc.IlOff < 0) { err = "cctor of <PrivateImplementationDetails> not found"; return false; }

        byte[] il = new byte[cc.IlSize];
        Array.Copy(b, cc.IlOff, il, 0, cc.IlSize);

        List<int> fieldRows = new List<int>();
        for (int i = 0; i + 4 < il.Length; i++)
            if (il[i] == 0xD0) {
                int tok = il[i + 1] | (il[i + 2] << 8) | (il[i + 3] << 16) | (il[i + 4] << 24);
                if ((tok & -16777216) == 0x04000000) fieldRows.Add(tok & 0xFFFFFF);
            }
        if (fieldRows.Count == 0) { err = "no ldtoken field in cctor (unknown blob shape)"; return false; }

        List<int> consts = new List<int>();
        int blobLen = 0;
        for (int i = 0; i + 4 < il.Length; i++)
            if (il[i] == 0x20) {
                int v = il[i + 1] | (il[i + 2] << 8) | (il[i + 3] << 16) | (il[i + 4] << 24);
                if (v > 100000 && v < 20000000) { if (v > blobLen) blobLen = v; }
                else if (v > 0 && v < 4096) consts.Add(v);
            }
        for (int i = 0; i + 1 < il.Length; i++)
            if (il[i] == 0x1F && il[i + 1] > 0) consts.Add(il[i + 1]);
        for (int i = 0; i < il.Length; i++)
            if (il[i] >= 0x16 && il[i] <= 0x1E) consts.Add(il[i] - 0x16);
        List<int> uc = new List<int>();
        for (int i = 0; i < consts.Count; i++) if (!uc.Contains(consts[i])) uc.Add(consts[i]);
        consts = uc;
        if (blobLen == 0) blobLen = 600000;

        List<int> sCands = new List<int>();
        for (int i = 4; i + 2 <= b.Length; i++) {
            int fr = U16(b, i);
            if (!fieldRows.Contains(fr)) continue;
            int rva = U32(b, i - 4);
            if (rva <= 0) continue;
            int off = Rva2Off(rva);
            if (off > 0 && off < b.Length) if (!sCands.Contains(off)) sCands.Add(off);
        }
        if (sCands.Count == 0) { err = "blob FieldRVA row not located"; return false; }

        List<Cipher> cs = new List<Cipher>();
        for (int i = 0; i < consts.Count; i++) {
            int C = consts[i];
            cs.Add(new Cipher { Name = "xor(i^" + C + ")", Xor = true,  C1 = C, Mode = 0 });
            cs.Add(new Cipher { Name = "xor(i+" + C + ")", Xor = true,  C1 = C, Mode = 1 });
            cs.Add(new Cipher { Name = "xor(i-" + C + ")", Xor = true,  C1 = C, Mode = 2 });
            cs.Add(new Cipher { Name = "add(i^" + C + ")", Xor = false, C1 = C, Mode = 4 });
            cs.Add(new Cipher { Name = "sub(i^" + C + ")", Xor = false, C1 = C, Mode = 5 });
        }
        cs.Add(new Cipher { Name = "identity", Xor = true, C1 = 0, Mode = 6 });

        int bestScore = -1;
        for (int si = 0; si < sCands.Count; si++) {
            int S = sCands[si];
            int n = Math.Min(blobLen, b.Length - S);
            if (n < 4096) continue;
            for (int ci = 0; ci < cs.Count; ci++) {
                Cipher c = cs[ci];
                byte[] pl = new byte[n];
                for (int i = 0; i < n; i++) pl[i] = Dec(c.Mode, c.C1, b[S + i], i);
                int printable = 0;
                for (int i = 0; i < n; i++) {
                    byte x = pl[i];
                    if ((x >= 32 && x < 127) || x == 9 || x == 10 || x == 13 || x == 0) printable++;
                }
                int score = (int)(printable * 1000L / n);
                if (fromB != null && IndexOf(pl, fromB, 0) >= 0) score += 100000;
                if (score > bestScore) {
                    bestScore = score;
                    baseS = S; cname = c.Name; xorOk = c.Xor; c1 = c.C1; cmode = c.Mode; plain = pl;
                }
            }
        }
        if (baseS < 0) { err = "no blob candidate scanned"; return false; }
        return true;
    }

    // ---------------- main ----------------
    public static string Run(string path, bool apply, string fromText, string toText) {
        StringBuilder rep = new StringBuilder();
        SBP p = new SBP();
        p.Load(path);
        rep.AppendLine("INFO\tmethods\t" + p.Methods.Count);
        rep.AppendLine("INFO\tsize\t" + p.b.Length);
        int changes = 0;

        for (int i = 0; i < GateNames.Length; i++) {
            string full = GateNames[i];
            int want = GateValues[i];
            List<Meth> hits = p.Find(full);
            if (hits.Count == 0) { rep.AppendLine("SKIP\tgate\t" + full + "\tnot-found"); continue; }
            for (int h = 0; h < hits.Count; h++) {
                Meth m = hits[h];
                if (m.HdrOff < 0) { rep.AppendLine("SKIP\tgate\t" + full + "\trow=" + m.Row + "\tno-body"); continue; }
                if (m.IlSize <= 2) { rep.AppendLine("SKIP\tgate\t" + full + "\trow=" + m.Row + "\talready-stub(il=" + m.IlSize + ")"); continue; }
                string rt = p.SigReturn(m);
                if (GateIsBool[i] && rt != "bool") { rep.AppendLine("SKIP\tgate\t" + full + "\trow=" + m.Row + "\tret=" + rt + " (not bool)"); continue; }
                int[] stub = WantStub(want);
                if (apply) p.WriteBody(m, stub);
                changes++;
                rep.AppendLine("CHANGE\tgate\t" + full + "\trow=" + m.Row + "\ttok=" + m.Token +
                               "\trva=0x" + m.Rva.ToString("X") + "\tilOld=" + m.IlSize + "\tilNew=" + stub.Length +
                               "\tstub=" + Hex(stub) + "\tret=" + rt);
            }
        }

        byte[] fromB = Encoding.UTF8.GetBytes(fromText);
        byte[] toB   = Encoding.UTF8.GetBytes(toText);
        int baseS; string cname; bool xorOk; int c1, cmode; byte[] plain; string err;
        if (p.DiscoverBlob(fromB, out baseS, out cname, out xorOk, out c1, out cmode, out plain, out err)) {
            rep.AppendLine("INFO\tblob\tbase=" + baseS + "\tcipher=" + cname + "\twritable=" + (xorOk ? "yes" : "no"));
            int n = 0, first = IndexOf(plain, fromB, 0);
            int scan = first;
            while (scan >= 0) { n++; scan = IndexOf(plain, fromB, scan + 1); }
            if (first < 0) rep.AppendLine("SKIP\tlabel\t'" + fromText + "' not present in blob");
            else if (!xorOk) rep.AppendLine("SKIP\tlabel\tcipher is not xor, cannot re-encode safely");
            else {
                byte[] target = new byte[fromB.Length];
                for (int k = 0; k < target.Length; k++) target[k] = (k < toB.Length) ? toB[k] : (byte)0x20;
                if (apply)
                    for (int k = 0; k < target.Length; k++)
                        p.b[baseS + first + k] = (byte)(target[k] ^ KeyByte(cmode, c1, first + k));
                changes++;
                rep.AppendLine("CHANGE\tlabel\tblob@" + first + "\tfileOff=" + (baseS + first) +
                               "\t'" + fromText + "' -> '" + Encoding.UTF8.GetString(target) + "'\toccurrences=" + n);
            }
        } else rep.AppendLine("SKIP\tlabel\t" + err);

        if (apply && changes > 0) { p.Save(path); rep.AppendLine("INFO\tsaved\t" + path); }
        rep.AppendLine("INFO\tchanges\t" + changes);
        return rep.ToString();
    }
}
'@

function Invoke-Engine([string]$path, [bool]$apply) {
    $report = [SBP]::Run($path, $apply, $FromText, $ToText)
    $changes = 0
    $lines = @()
    foreach ($ln in ($report -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($ln)) { continue }
        $lines += $ln
        $f = $ln -split "`t"
        if ($f[0] -eq 'CHANGE') { $changes++ }
    }
    return @{ Lines = $lines; Changes = $changes; Report = $report }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
if (-not (Test-Path -LiteralPath $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

if (-not (Test-Path -LiteralPath $Dll)) {
    Write-Log "ServBay.dll not found: $Dll" 'ERROR'
    exit 1
}

$fi  = Get-Item -LiteralPath $Dll
$cur = (Get-FileHash -LiteralPath $Dll -Algorithm SHA256).Hash
$ver = $fi.VersionInfo.FileVersion

$state = $null
if (Test-Path -LiteralPath $StatePath) {
    try { $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json } catch { $state = $null }
}

# fast path -- nothing on disk changed since the last successful patch
if ($state -and $state.ok -and $state.sha256 -eq $cur -and -not $DryRun) {
    if (-not $Quiet) { Write-Log ("up to date v{0} sha={1}" -f $ver, $cur.Substring(0,12)) }
    exit 0
}

Write-Log ("inspecting ServBay.dll v{0} sha={1} size={2}" -f $ver, $cur.Substring(0,12), $fi.Length)

Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop

$dry = Invoke-Engine $Dll $false
foreach ($ln in $dry.Lines) { Write-Log ("  " + $ln) 'TRACE' }

if ($dry.Changes -eq 0) {
    Write-Log "no changes needed -- binary already patched" 'OK'
    if (-not $DryRun) {
        [pscustomobject]@{ ok = $true; sha256 = $cur; version = $ver; patchedUtc = (Get-Date).ToUniversalTime().ToString('o'); changes = 0 } |
            ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding UTF8
    }
    exit 0
}

if ($DryRun) {
    Write-Log ("DRY RUN: {0} change(s) would be applied" -f $dry.Changes) 'OK'
    exit 0
}

# --- backup pristine binary (first time this version is seen) ---------------
$pristine = -not ($dry.Lines | Where-Object { $_ -match 'gate.*CHANGE' })
if ($pristine) {
    $bk = Join-Path $BackupDir ('ServBay.' + $ver + '.' + $cur.Substring(0,8) + '.dll')
    if (-not (Test-Path -LiteralPath $bk)) {
        Copy-Item -LiteralPath $Dll -Destination $bk -Force
        Write-Log "pristine backup -> $bk"
    }
} else {
    Write-Log "binary was partially patched; no pristine backup taken" 'WARN'
}

# --- apply -----------------------------------------------------------------
$wasRunning = $false
if (-not $NoStop) { $wasRunning = Stop-ServBay }
Start-Sleep -Milliseconds 500

try { Invoke-Engine $Dll $true | Out-Null }
catch { Write-Log ("patch failed: " + $_.Exception.Message) 'ERROR'; if ($wasRunning -and -not $NoStop) { Start-ServBay }; exit 2 }

$verify = Invoke-Engine $Dll $false
if ($verify.Changes -ne 0) {
    Write-Log ("verification failed -- {0} change(s) still pending; restoring" -f $verify.Changes) 'ERROR'
    if ($pristine) {
        Copy-Item -LiteralPath $bk -Destination $Dll -Force
        Write-Log "restored pristine build" 'ERROR'
    }
    if ($wasRunning -and -not $NoStop) { Start-ServBay }
    exit 3
}

$newHash = (Get-FileHash -LiteralPath $Dll -Algorithm SHA256).Hash
Write-Log ("patched OK -- {0} site(s), sha={1}" -f $dry.Changes, $newHash.Substring(0,12)) 'OK'

[pscustomobject]@{
    ok = $true; sha256 = $newHash; version = $ver;
    patchedUtc = (Get-Date).ToUniversalTime().ToString('o');
    changes = $dry.Changes;
    sites = @($dry.Lines | Where-Object { $_ -match '^CHANGE' })
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath -Encoding UTF8

if ($wasRunning -and -not $NoRestart) { Start-ServBay }
exit 0
