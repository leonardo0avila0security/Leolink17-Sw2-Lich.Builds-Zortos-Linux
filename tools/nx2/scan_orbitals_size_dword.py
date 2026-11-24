#!/usr/bin/env python3
"""Find all captured-memory occurrences of the exact DWORD feeding guest x25."""
import mmap,struct,sys

def parse(f,fs):
    f.seek(8); n=struct.unpack("<I",f.read(4))[0]; d=struct.unpack("<I",f.read(4))[0]
    streams={}
    for i in range(n):
        f.seek(d+i*12); t,s,r=struct.unpack("<III",f.read(12)); streams[t]=(s,r)
    rs=[]
    if 9 in streams:
        s,r=streams[9]; f.seek(r); n,p=struct.unpack("<QQ",f.read(16))
        for _ in range(n):
            a,z=struct.unpack("<QQ",f.read(16))
            if z and p+z<=fs: rs.append((a,z,p))
            p+=z
    if 5 in streams:
        s,r=streams[5]; f.seek(r); n=struct.unpack("<I",f.read(4))[0]
        for _ in range(n):
            a,z,o=struct.unpack("<QII",f.read(16))
            if z and o+z<=fs: rs.append((a,z,o))
    return rs

def main(path):
    with open(path,"rb") as f:
        f.seek(0,2); fs=f.tell()
        if f.read(0) is None: pass
        f.seek(0)
        if f.read(4)!=b"MDMP": raise SystemExit("not MDMP")
        rs=parse(f,fs)
        mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
        patterns=[
            ("x25_low32_01490140",bytes.fromhex("40 01 49 01")),
            ("bad_source_qword",struct.pack("<Q",0x01460149013D0140)),
        ]
        for name,needle in patterns:
            hits=[]
            for va,length,fo in rs:
                pos=mm.find(needle,fo,fo+length)
                while pos>=0:
                    hits.append((va+pos-fo,fo+(pos-fo)))
                    if len(hits)>=200: break
                    pos=mm.find(needle,pos+1,fo+length)
                if len(hits)>=200: break
            print(f"\n[{name}] hits={len(hits)} (cap 200)")
            for va,fo in hits:
                print(f"VA={va:#018x} file={fo:#x}")
                # short surrounding bytes, when fully inside this captured range
                rr=next((r for r in rs if r[0]<=va<r[0]+r[1]),None)
                if rr:
                    s,z,o=rr; lo=max(s,va-16); hi=min(s+z,va+32)
                    mmpos=o+lo-s
                    print(f"  around[{lo:#x}:{hi:#x}]={mm[mmpos:mmpos+hi-lo].hex()}")
        mm.close()
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: scan_orbitals_size_dword.py dump.dmp")
    main(sys.argv[1])
