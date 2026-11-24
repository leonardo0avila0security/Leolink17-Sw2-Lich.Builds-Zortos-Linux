#!/usr/bin/env python3
"""Probe guest array records, size-load provenance, and signed branch inputs."""
import struct,sys

def parse(f):
    f.seek(0,2); fs=f.tell(); f.seek(0)
    if f.read(4)!=b"MDMP": raise ValueError("not MDMP")
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
    return sorted(rs),fs,streams

def rv(f,rs,a,n):
    out=bytearray(); p=a; end=a+n
    while p<end:
        hits=[x for x in rs if x[0]<=p<x[0]+x[1]]
        if not hits:return None
        b,z,o=max(hits,key=lambda x:x[0]+x[1]); k=min(end,b+z)-p
        f.seek(o+p-b); q=f.read(k)
        if len(q)!=k:return None
        out.extend(q);p+=k
    return bytes(out)

def u32(b,o=0): return struct.unpack_from("<I",b,o)[0]
def u64(b,o=0): return struct.unpack_from("<Q",b,o)[0]
def s32(v): return struct.unpack("<i",struct.pack("<I",v&0xffffffff))[0]

def main(path):
    with open(path,"rb") as f:
        rs,fs,streams=parse(f)
        if 6 not in streams: raise SystemExit("ExceptionStream missing")
        _,er=streams[6]
        f.seek(er+164); cr=struct.unpack("<I",f.read(4))[0]
        f.seek(cr+168); rsi=struct.unpack("<Q",f.read(8))[0]
        ctx=rv(f,rs,rsi,0x400)
        if ctx is None: raise SystemExit("fault descriptor not captured")
        print(f"dump_size={fs} ranges={len(rs)} context={rsi:#x}")
        print(f"source_candidate={u64(ctx,0xD0):#x} x27_candidate={u64(ctx,0xD8):#x}")
        for off in (0x98,0xA8):
            x21=u64(ctx,off); obj=rv(f,rs,x21,0x500)
            print(f"\n[CANDIDATE x21 context+{off:#x}] x21={x21:#x} captured={obj is not None}")
            if obj is None: continue
            arr=rv(f,rs,x21+0x158,8); lim=rv(f,rs,x21+0x160,4)
            if arr is None or lim is None:
                print("array base/limit not captured"); continue
            base=u64(arr); count=min(u32(lim),4096)
            print(f"array_base={base:#x} record_limit={u32(lim)} scan_limit={count}")
            for idx in range(count):
                addr=base+idx*0xE8; rec=rv(f,rs,addr,0xE0)
                if rec is None:
                    print(f"record[{idx}]={addr:#x} NOT_CAPTURED"); continue
                dptr=u64(rec,0xD0); d8=u32(rec,0xD8); si=s32(d8)
                chosen=dptr if dptr else addr+0x10
                x8=(chosen+(si<<6))&0xffffffffffffffff
                load_addr=(x8-8)&0xffffffffffffffff
                val=rv(f,rs,load_addr,8); d=u64(val) if val else None
                mark=(load_addr==0x11C51F708 or (d is not None and (d&0xffffffff)==0x01490140))
                print(f"record[{idx}]={addr:#x} +D0={dptr:#x} +D8={d8:#x} signed={si} chosen={chosen:#x} x8={x8:#x} load={load_addr:#x} d0={('not-captured' if d is None else hex(d))}{' *** MATCH ***' if mark else ''}")
        x27=u64(ctx,0xD8)
        x29=u64(ctx,0xE8)
        x29m8=rv(f,rs,x29-8,8) if x29>=8 else None
        array_ptr=u64(x29m8) if x29m8 else 0
        loop_index=u64(ctx,0xC0)
        index_addr=array_ptr+loop_index*8
        index_data=rv(f,rs,index_addr,4) if array_ptr else None
        w9=s32(u32(index_data)) if index_data else None
        w8data=rv(f,rs,x27+0xD8,4) if x27 else None
        w8=s32(u32(w8data)) if w8data else None
        flag60=u64(ctx,0x60)&1
        print("\n[BRANCH COMPARISON]")
        print(f"x29={x29:#x} [x29-8]={array_ptr:#x} loop_index={loop_index:#x} index_addr={index_addr:#x} w9={w9}")
        print(f"x27={x27:#x} w8_at_x27_plus_D8={w8} context+0x60.bit0={flag60}")
        print(f"signed_w9_lt_w8={(w9 is not None and w8 is not None and w9<w8)} combined_with_flag={(w9 is not None and w8 is not None and w9<w8 and flag60==1)}")
        sp=u64(ctx,0x100)-0x120
        print("\n[guest stack locals]")
        for off in (0x20,0x38,0x80,0x88,0x90,0x98,0xA0,0xA8,0xB0,0xB8,0xC0,0xC8,0xD0):
            v=rv(f,rs,sp+off,8)
            print(f"sp+{off:#x}={u64(v) if v else 'not-captured'}")

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: probe_orbitals_size_field.py dump.dmp")
    main(sys.argv[1])
