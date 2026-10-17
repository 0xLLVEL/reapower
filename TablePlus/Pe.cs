using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public class Sec {
    public string Name; public uint VA, VSize, RawPtr, RawSize;
    public override string ToString() {
        return string.Format("  {0,-9} VA 0x{1:X8}  VSize 0x{2:X8}  RawPtr 0x{3:X8}  RawSize 0x{4:X8}", Name, VA, VSize, RawPtr, RawSize);
    }
}

public class Pe {
    public byte[] B;
    public int PEOff, NumSections, OptSize, OptOff, SecOff;
    public ushort Machine;
    public uint EntryPoint, SizeOfImage, SizeOfHeaders, Timestamp;
    public bool Is64;
    public bool HasCli;
    public uint CliRva, CliSize;
    public uint MdRva, MdSize;      // CLI header fields
    public string[] SectionNames;
    public List<Sec> Sections = new List<Sec>();

    public static uint U16(byte[] b, int o) { return (uint)(b[o] | (b[o+1] << 8)); }
    public static uint U32(byte[] b, int o) {
        return (uint)((uint)b[o] | ((uint)b[o+1] << 8) | ((uint)b[o+2] << 16) | ((uint)b[o+3] << 24));
    }
    public static ulong U64(byte[] b, int o) {
        return (ulong)U32(b, o) | ((ulong)U32(b, o+4) << 32);
    }

    public void Load(string path) {
        B = File.ReadAllBytes(path);
        Parse();
    }

    public void Parse() {
        PEOff = (int)U32(B, 0x3C);
        if (B[PEOff] != 'P' || B[PEOff+1] != 'E') throw new Exception("not PE");
        Machine       = (ushort)U16(B, PEOff + 4);
        NumSections   = (int)U16(B, PEOff + 6);
        Timestamp     = U32(B, PEOff + 8);
        OptSize       = (int)U16(B, PEOff + 20);
        OptOff        = PEOff + 24;
        ushort magic  = (ushort)U16(B, OptOff);
        Is64          = (magic == 0x20B);
        EntryPoint    = U32(B, OptOff + 16);
        SizeOfImage   = U32(B, OptOff + 56);
        SizeOfHeaders = U32(B, OptOff + 60);
        SecOff        = OptOff + OptSize;
        int ddOff     = OptOff + (Is64 ? 112 : 96);
        CliRva        = U32(B, ddOff + 14 * 8);
        CliSize       = U32(B, ddOff + 14 * 8 + 4);
        HasCli        = CliRva != 0;
        for (int i = 0; i < NumSections; i++) {
            int o = SecOff + i * 40;
            Sec s = new Sec();
            char[] nm = new char[8];
            for (int k = 0; k < 8; k++) nm[k] = (char)B[o+k];
            s.Name = new string(nm).TrimEnd('\0');
            s.VSize   = U32(B, o + 8);
            s.VA      = U32(B, o + 12);
            s.RawSize = U32(B, o + 16);
            s.RawPtr  = U32(B, o + 20);
            Sections.Add(s);
        }
        if (HasCli) {
            int co = Rva2Off(CliRva);
            MdRva  = U32(B, co + 8);
            MdSize = U32(B, co + 12);
        }
    }

    public int Rva2Off(uint rva) {
        foreach (Sec s in Sections) {
            if (rva >= s.VA && rva < s.VA + s.VSize) return (int)(s.RawPtr + (rva - s.VA));
        }
        return -1;
    }

    public string Report() {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("  size           " + B.Length.ToString("N0"));
        sb.AppendLine("  machine        0x" + Machine.ToString("X4") + (Machine == 0x8664 ? "  (x64)" : Machine == 0x14C ? "  (x86)" : ""));
        sb.AppendLine("  pe32+          " + Is64);
        sb.AppendLine("  entry point    0x" + EntryPoint.ToString("X8"));
        sb.AppendLine("  sizeOfImage    0x" + SizeOfImage.ToString("X8"));
        sb.AppendLine("  timestamp      0x" + Timestamp.ToString("X8") + "  (" + (Timestamp > 0 ? DateTimeOffset.FromUnixTimeSeconds(Timestamp).ToString("u") : "?") + ")");
        sb.AppendLine("  sections       " + NumSections);
        foreach (Sec s in Sections) sb.AppendLine(s.ToString());
        sb.AppendLine("  CLI header     " + (HasCli ? ("rva 0x" + CliRva.ToString("X8") + " size 0x" + CliSize.ToString("X") + " -> file 0x" + Rva2Off(CliRva).ToString("X")) : "ABSENT (native image)"));
        if (HasCli) {
            sb.AppendLine("  metadata rva   0x" + MdRva.ToString("X8") + " size 0x" + MdSize.ToString("X") + " -> file 0x" + Rva2Off(MdRva).ToString("X"));
            int mo = Rva2Off(MdRva);
            if (mo > 0) sb.AppendLine("  metadata magic " + Asc(mo + 4, 4));
        }
        // .NET single-file bundle footer: last 32 bytes
        int t = B.Length - 32;
        sb.AppendLine("  tail48         " + Hex(t + 16, 32));
        sb.AppendLine("  bundle sig?    0x" + U64(B, B.Length - 8).ToString("X16") + "  (expect 0x8B12FDD7A9E1C1E2)");
        return sb.ToString();
    }

    public string Hex(int off, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + n && i < B.Length; i++) sb.Append(B[i].ToString("X2"));
        return sb.ToString();
    }
    public string Asc(int off, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + n && i < B.Length; i++) {
            byte c = B[i];
            sb.Append((c >= 32 && c < 127) ? (char)c : '.');
        }
        return sb.ToString();
    }

    public string FindCI(string needle, int limit, int ctx) {
        byte[] n = Encoding.ASCII.GetBytes(needle.ToLowerInvariant());
        StringBuilder sb = new StringBuilder();
        int c = 0;
        for (int i = 0; i + n.Length <= B.Length; i++) {
            byte b0 = B[i];
            if (b0 >= 65 && b0 <= 90) b0 = (byte)(b0 + 32);
            if (b0 != n[0]) continue;
            bool ok = true;
            for (int k = 1; k < n.Length; k++) {
                byte bk = B[i+k];
                if (bk >= 65 && bk <= 90) bk = (byte)(bk + 32);
                if (bk != n[k]) { ok = false; break; }
            }
            if (!ok) continue;
            c++;
            if (c <= limit) {
                sb.AppendLine("    @0x" + i.ToString("X8") + "  " + Asc(i - ctx < 0 ? 0 : i - ctx, ctx) + "[" + needle + "]" + Asc(i + n.Length, ctx));
            }
        }
        sb.AppendLine("    total '" + needle + "' = " + c);
        return sb.ToString();
    }

    public string Find(string needle, int limit, int ctx) {
        byte[] n = Encoding.ASCII.GetBytes(needle);
        StringBuilder sb = new StringBuilder();
        int c = 0;
        for (int i = 0; i + n.Length <= B.Length; i++) {
            if (B[i] != n[0]) continue;
            bool ok = true;
            for (int k = 1; k < n.Length; k++) if (B[i+k] != n[k]) { ok = false; break; }
            if (!ok) continue;
            c++;
            if (c <= limit) {
                sb.AppendLine("    @0x" + i.ToString("X8") + "  " + Asc(i - ctx < 0 ? 0 : i - ctx, ctx) + "[" + needle + "]" + Asc(i + n.Length, ctx));
            }
        }
        sb.AppendLine("    total '" + needle + "' = " + c);
        return sb.ToString();
    }
}
