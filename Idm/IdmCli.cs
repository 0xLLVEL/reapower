using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// IdmCli - PE section scanner + in-memory byte patcher.
//
// IDMan.exe is a native x86 PE: there are no metadata tables, no MethodDef rows
// and no method names to re-find after an update, so the .NET-style identity
// model used for IL patching does not apply. What survives an IDM update is the
// *code*, so identity here is a byte signature located by scanning a section.
//
// This class owns only the mechanical parts: parse the PE section table, scan a
// section for a signature, read/write bytes in the buffer, hash regions. Every
// decision (which tier, whether to patch, whether to refuse) stays in the
// engine, IdmPatch.ps1.
public class IdmCli
{
    byte[] _buf;
    string _path;

    public int   Machine;     // 0x14C = i386
    public uint  ImageBase;
    public uint  TimeDateStamp;
    public int   SectionCount;
    public List<string> Lines = new List<string>();

    struct Sec { public string Name; public uint VA, VSize, RawPtr, RawSize; }
    readonly List<Sec> _secs = new List<Sec>();

    public void Load(string path)
    {
        _path = path;
        _buf  = File.ReadAllBytes(path);

        if (_buf.Length < 0x40 || _buf[0] != 0x4D || _buf[1] != 0x5A)
            throw new InvalidDataException("not a PE file (no MZ stub)");

        int lfanew = BitConverter.ToInt32(_buf, 0x3C);
        if (lfanew <= 0 || lfanew + 24 > _buf.Length)
            throw new InvalidDataException("corrupt e_lfanew " + lfanew);

        if (BitConverter.ToUInt32(_buf, lfanew) != 0x00004550)
            throw new InvalidDataException("not a PE file (no PE\\0\\0 signature)");

        int coff = lfanew + 4;
        Machine       = BitConverter.ToUInt16(_buf, coff);
        int nsec      = BitConverter.ToUInt16(_buf, coff + 2);
        TimeDateStamp = BitConverter.ToUInt32(_buf, coff + 4);
        int optsz     = BitConverter.ToUInt16(_buf, coff + 16);
        int opt       = coff + 20;

        if (optsz < 68) throw new InvalidDataException("optional header too small (" + optsz + ")");
        ImageBase = BitConverter.ToUInt32(_buf, opt + 28);

        int secoff = opt + optsz;
        if (secoff + nsec * 40 > _buf.Length)
            throw new InvalidDataException("section table runs past end of file");

        _secs.Clear();
        Lines.Clear();
        SectionCount = nsec;
        for (int i = 0; i < nsec; i++)
        {
            int o = secoff + i * 40;
            var s = new Sec();
            s.Name    = Encoding.ASCII.GetString(_buf, o, 8).TrimEnd('\0');
            s.VSize   = BitConverter.ToUInt32(_buf, o + 8);
            s.VA      = BitConverter.ToUInt32(_buf, o + 12);
            s.RawSize = BitConverter.ToUInt32(_buf, o + 16);
            s.RawPtr  = BitConverter.ToUInt32(_buf, o + 20);
            _secs.Add(s);
            Lines.Add(string.Format(
                "{0,-8} VA=0x{1:X8} VSize=0x{2:X8} RawPtr=0x{3:X8} RawSize=0x{4:X8}",
                s.Name, s.VA, s.VSize, s.RawPtr, s.RawSize));
        }
    }

    public long Length { get { return _buf == null ? 0 : _buf.Length; } }

    // file offset -> section name, or null when the offset is in no raw section
    public string SectionOfOffset(long off)
    {
        foreach (var s in _secs)
            if (off >= s.RawPtr && off < (long)s.RawPtr + s.RawSize) return s.Name;
        return null;
    }

    // every file offset inside <secName> whose bytes equal <sigHex>, in ascending order.
    // returns -1 when the section does not exist.
    public int[] FindInSection(string secName, string sigHex)
    {
        Sec? found = null;
        foreach (var s in _secs) if (s.Name == secName) { found = s; break; }
        if (found == null) return new int[] { -1 };

        byte[] sig = FromHex(sigHex);
        Sec sec = found.Value;
        int start = (int)sec.RawPtr;
        int end   = start + (int)sec.RawSize;
        if (end > _buf.Length) end = _buf.Length;

        var hits = new List<int>();
        for (int i = start; i + sig.Length <= end; i++)
        {
            bool ok = true;
            for (int j = 0; j < sig.Length; j++)
                if (_buf[i + j] != sig[j]) { ok = false; break; }
            if (ok) hits.Add(i);
        }
        return hits.ToArray();
    }

    public string ReadHex(long off, int len)
    {
        if (off < 0 || off + len > _buf.Length)
            throw new ArgumentOutOfRangeException("off", "read past end of file");
        var sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) sb.Append(_buf[off + i].ToString("x2"));
        return sb.ToString();
    }

    public bool RegionEquals(long off, string hex)
    {
        byte[] want = FromHex(hex);
        if (off < 0 || off + want.Length > _buf.Length) return false;
        for (int i = 0; i < want.Length; i++)
            if (_buf[off + i] != want[i]) return false;
        return true;
    }

    public void WriteBytes(long off, string patchHex)
    {
        byte[] patch = FromHex(patchHex);
        if (off < 0 || off + patch.Length > _buf.Length)
            throw new ArgumentOutOfRangeException("off", "write past end of file");
        Array.Copy(patch, 0, _buf, off, patch.Length);
    }

    public string ShaRange(long off, int len)
    {
        using (var sha = SHA256.Create())
            return ToHex(sha.ComputeHash(_buf, (int)off, len));
    }

    public string BufferSha()
    {
        using (var sha = SHA256.Create())
            return ToHex(sha.ComputeHash(_buf));
    }

    public void Save(string path) { File.WriteAllBytes(path, _buf); }

    static string ToHex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }

    static byte[] FromHex(string hex)
    {
        if (hex == null || hex.Length % 2 != 0)
            throw new ArgumentException("hex string must have an even length");
        var outb = new byte[hex.Length / 2];
        for (int i = 0; i < outb.Length; i++)
            outb[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return outb;
    }
}
