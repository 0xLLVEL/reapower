using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

public class Usx3 {
    byte[] b;
    int[] va, vsz, rp, rsz;

    public int MdBase, UsBase, UsSize, UsEntryPos = -1, UsSizePos = -1, BlobBase, BlobSize, StringsBase, StringsSize;
    public List<string> Streams = new List<string>();

    ushort U16(int o){ return BitConverter.ToUInt16(b,o); }
    uint   U32(int o){ return BitConverter.ToUInt32(b,o); }

    int R2O(uint rva){
        for(int i=0;i<va.Length;i++)
            if(rva>=(uint)va[i] && rva < (uint)va[i]+(uint)Math.Max(vsz[i],rsz[i])) return (int)(rva - (uint)va[i] + (uint)rp[i]);
        return -1;
    }

    public void Load(string path){
        b = File.ReadAllBytes(path);
        uint pe = U32(0x3C);
        int coff = (int)pe + 4;
        int numSec = (int)U16(coff+2);
        int optSize = (int)U16(coff+16);
        int optOff = coff + 20;
        int secTab = optOff + optSize;
        va=new int[numSec]; vsz=new int[numSec]; rp=new int[numSec]; rsz=new int[numSec];
        for(int i=0;i<numSec;i++){ int s=secTab+i*40;
            vsz[i]=(int)U32(s+8); va[i]=(int)U32(s+12); rsz[i]=(int)U32(s+16); rp[i]=(int)U32(s+20); }

        int dirBase = optOff + 112;
        int cliOff = R2O(U32(dirBase + 14*8));
        int mdRva  = (int)U32(cliOff + 8);
        MdBase = R2O((uint)mdRva);
        int verLen = (int)U32(MdBase + 12);
        int p = MdBase + 16 + verLen + 2;
        int nsCount = (int)U16(p); p += 2;
        for(int i=0;i<nsCount;i++){
            int entry = p;
            uint soff = U32(p);
            uint ssize = U32(p+4);
            p += 8;
            StringBuilder sb = new StringBuilder();
            while(b[p]!=0){ sb.Append((char)b[p]); p++; }
            p++;
            p = (int)Math.Ceiling(p/4.0)*4;
            string nm = sb.ToString();
            int abs = MdBase + (int)soff;
            Streams.Add(string.Format("{0} off={1} size={2} end={3} entryPos={4}", nm, abs, ssize, abs+ssize, entry));
            if(nm=="#US"){ UsBase=abs; UsSize=(int)ssize; UsEntryPos=entry; UsSizePos=entry+4; }
            if(nm=="#Blob"){ BlobBase=abs; BlobSize=(int)ssize; }
            if(nm=="#Strings"){ StringsBase=abs; StringsSize=(int)ssize; }
        }
    }
}
