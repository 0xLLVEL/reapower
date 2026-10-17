using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public class BlobDec {
    public const int S = 14180902;

    public static byte[] Plain(string path) {
        byte[] b = File.ReadAllBytes(path);
        byte[] o = new byte[501022];
        for (int i = 0; i < o.Length; i++) o[i] = (byte)(b[S + i] ^ ((i ^ 170) & 0xFF));
        return o;
    }

    public static string At(byte[] p, int off, int len) {
        return Encoding.UTF8.GetString(p, off, Math.Min(len, p.Length - off));
    }

    public static string Report(string path) {
        byte[] p = Plain(path);
        StringBuilder sb = new StringBuilder();
        int[][] items = new int[][] {
            new int[]{359672,12}, new int[]{359684,11}, new int[]{359695,12},
            new int[]{329651,12}, new int[]{272947,26}, new int[]{25008,30},
            new int[]{359670,40} 
        };
        foreach (var it in items) sb.AppendLine(string.Format("  blob[{0},len {1}] = '{2}'", it[0], it[1], At(p, it[0], it[1]).Replace("\n","\\n").Replace("\r","\\r")));

        // every occurrence of "ServBay" inside the blob
        string all = Encoding.UTF8.GetString(p);
        sb.AppendLine("  --- occurrences of 'ServBay' in the blob (offset, excerpt) ---");
        int idx = 0; int n = 0;
        while ((idx = all.IndexOf("ServBay", idx)) >= 0 && n < 60) {
            int a = Math.Max(0, idx - 8), len = Math.Min(60, all.Length - a);
            string seg = all.Substring(a, len).Replace("\0",".").Replace("\n","\\n").Replace("\r","");
            sb.AppendLine(string.Format("    [{0}] ...{1}", idx, seg));
            idx += 7; n++;
        }
        return sb.ToString();
    }
}
