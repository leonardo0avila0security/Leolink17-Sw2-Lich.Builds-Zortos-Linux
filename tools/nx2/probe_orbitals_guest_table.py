#!/usr/bin/env python3
"""Resolve the guest x27 record and exact load that feeds memcpy length."""
import struct,sys

def parse(f):
    f.seek(0,2); fsize=f.tell(); f.seek(0)
    if f.read(4)!=b"MDMP": raise ValueError("not MDMP")
    f.seek(8); n=struct.unpack("<I",f.read(4))[0]; drva=struct.unpack("<I",f.read(4))[0]
    streams={}
    for i in range(n):
        f.seek(drva+i*12); typ,sz,rva=struct.unpack("<III",f.read(12)); streams[typ]=(sz,rva)
    ranges=[]
    if 9 in streams:
        sz,rva=streams[9]; f.seek(rva); count,cur=struct.unpack("<QQ",f.read(16))
        for _ in range(count):
            va,length=struct.unpack("<QQ",f.read(16)); ranges.append((va,length,cur)); cur+=length
    if 5 in streams:
        sz,rva=streams[5]; f.seek(rva); count=struct.unpack("<I",f.read(4))[0]
        for _ in range(count):
            va,length,fo=struct.unpack("<QII",f.read(16))
            if length:ranges.append((va,length,fo))
    return ranges,fsize

def all_values(f,ranges,addr,n=8):
    hits=[]
    for s,l,o in ranges:
        if s<=addr and addr+n<=s+l:
            f.seek(o+addr-s); raw=f.read(n)
            if len(raw)==n: hits.append((s,l,o,int.from_bytes(raw,"little"),raw.hex()))
    return hits

def s32(v): return struct.unpack("<i",struct.pack("<I",v&0xffffffff))[0]

def show(f,ranges,label,addr,n=8):
    vals=all_values(f,ranges,addr,n)
    print(f"\n[{label}] VA={addr:#x} overlaps={len(vals)}")
    for s,l,o,v,raw in vals:
        print(f"range={s:#x}+{l:#x} file={o+addr-s:#x} raw={raw} value={v:#018x}")
    return vals

def main(path):
    with open(path,"rb") as f:
        ranges,fsize=parse(f)
        print(f"dump_size={fsize:,} memory_ranges={len(ranges)}")
        # Values recovered from the faulting host context and guest register spill.
        x21=0x0E40012810
        x27=0x0CE01F2C00
        print(f"ASSUMED_GUEST_X21={x21:#x} ASSUMED_GUEST_X27={x27:#x}")
        bases=show(f,ranges,"x21+0x158 (guest ldr x9,[x21,#0x158])",x21+0x158)
        show(f,ranges,"x27+0xD0 (guest ldr x9,[x27,#0xD0])",x27+0xD0)
        counts=show(f,ranges,"x27+0xD8 (guest ldr w8,[x27,#0xD8])",x27+0xD8)
        load_addr=x27-0xB8
        d0s=show(f,ranges,"d0 load at x8-8 (if w8=-3 and x9==0)",load_addr)
        print("\n[INDEX CONSISTENCY]")
        for _,_,_,base,_ in bases:
            delta=x27-base
            print(f"base={base:#x} x27-base={delta:#x} index={(delta//0xE8 if delta>=0 and delta%0xE8==0 else 'not a nonnegative multiple of 0xE8')}")
        print("\n[DERIVED GUEST VALUES]")
        for _,_,_,raw,_ in counts:
            w8=s32(raw)
            for _,_,_,base,_ in bases:
                # Guest csel chooses x27+0x10 when x21+0x158 is zero.
                if base==0:
                    selected=x27+0x10
                else:
                    selected=base
                x8=(selected+(w8<<6))&0xffffffffffffffff
                addr=(x8-8)&0xffffffffffffffff
                print(f"base={base:#x} w8={w8} selected={selected:#x} x8={x8:#x} load={addr:#x}")
        for _,_,_,v,_ in d0s:
            count=s32(v)
            print(f"d0={v:#018x} low_s32={count:#x} x2=(x25<<2)={(count*4)&0xffffffffffffffff:#x}")
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: probe_orbitals_guest_table.py dump.dmp")
    main(sys.argv[1])
