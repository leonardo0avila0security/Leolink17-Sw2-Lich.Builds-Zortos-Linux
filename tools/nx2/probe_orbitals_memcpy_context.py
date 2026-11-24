#!/usr/bin/env python3
"""Probe the expected memcpy source and context sharing in Orbitals dump 16952."""
import mmap
import struct
import sys
from pathlib import Path

MDMP = 0x504D444D

def read_at(f, off, size):
    f.seek(off)
    data=f.read(size)
    if len(data)!=size:
        raise ValueError(f"short read at {off:#x}")
    return data

def u32(f, off): return struct.unpack("<I",read_at(f,off,4))[0]
def u64(f, off): return struct.unpack("<Q",read_at(f,off,8))[0]

def streams(f, size):
    if u32(f,0)!=MDMP: raise ValueError("not MDMP")
    count=u32(f,8); directory=u32(f,12); out={}
    for i in range(count):
        typ,n,rva=struct.unpack("<III",read_at(f,directory+i*12,12))
        if rva<=size and n<=size-rva: out.setdefault(typ,(rva,n))
    return out

def ranges(f, ss, size):
    out=[]
    if 9 in ss:
        rva,n=ss[9]; count=u64(f,rva); pos=u64(f,rva+8)
        for i in range(count):
            va,nbytes=struct.unpack("<QQ",read_at(f,rva+16+i*16,16))
            if nbytes and pos<=size and nbytes<=size-pos: out.append((va,nbytes,pos))
            pos+=nbytes
    if 5 in ss:
        rva,n=ss[5]; count=u32(f,rva)
        for i in range(count):
            va,nbytes,fo=struct.unpack("<QII",read_at(f,rva+4+i*16,16))
            if nbytes and fo<=size and nbytes<=size-fo: out.append((va,nbytes,fo))
    return sorted(out)

def read_virtual(f, rs, va, n):
    pos=va; out=bytearray()
    while len(out)<n:
        candidates=[r for r in rs if r[0]<=pos<r[0]+r[1]]
        if not candidates: return None
        start,length,filepos=max(candidates,key=lambda r:r[0]+r[1])
        take=min(n-len(out),start+length-pos)
        out+=read_at(f,filepos+pos-start,take)
        pos+=take
    return bytes(out)

def main(path):
    size=Path(path).stat().st_size
    with open(path,"rb") as f:
        ss=streams(f,size); rs=ranges(f,ss,size)
        print(f"DUMP_SIZE={size:,} ranges={len(rs)}")
        if 6 not in ss: raise SystemExit("no exception stream")
        ex,_=ss[6]
        tid=u32(f,ex)
        code=u32(f,ex+8)
        address=u64(f,ex+24)
        ctx_size=u32(f,ex+160); ctx_rva=u32(f,ex+164)
        ctx=read_at(f,ctx_rva,min(ctx_size,0x1000))
        regs={name:struct.unpack_from("<Q",ctx,off)[0] for name,off in
              (("RCX",128),("RDX",136),("RSP",152),("RSI",168),("R8",184),("RIP",248))}
        print(f"EXCEPTION tid={tid:#x} code={code:#x} address={address:#x}")
        for k,v in regs.items(): print(f"{k}={v:#018x}")
        rsi=regs["RSI"]
        desc=read_virtual(f,rs,rsi,0x400)
        if desc is None: raise SystemExit("RSI descriptor not captured")
        q=lambda off: struct.unpack_from("<Q",desc,off)[0]
        for off in (0,8,0x10,0x40,0x48,0xC8,0xD0,0xD8,0xE0,0xE8,0xF0,0x100,0x138):
            print(f"DESC+{off:03X}={q(off):#018x}")
        base=q(0xD8); offset=q(0xC8); expected=(base+offset)&0xFFFFFFFFFFFFFFFF
        print(f"EXPECTED_SOURCE_FROM_GUEST_ADD=[rsi+0xD8]+[rsi+0xC8]={base:#x}+{offset:#x}={expected:#x}")
        data=read_virtual(f,rs,expected,0x100)
        print("EXPECTED_SOURCE_CAPTURED="+("yes" if data is not None else "no"))
        if data is not None: print("EXPECTED_SOURCE_HEX="+data.hex())
        candidate=0x11C51F700
        data=read_virtual(f,rs,candidate,0x100)
        print(f"BAD_SOURCE_CONTENT_LOCATION={candidate:#x} captured={data is not None}")
        if data is not None: print("BAD_SOURCE_CONTENT_HEX="+data.hex())
        # Check whether the faulting descriptor pointer appears on another thread's captured stack.
        shared=[]
        if 3 in ss:
            tr,_=ss[3]; count=u32(f,tr)
            needle=struct.pack("<Q",rsi)
            for i in range(count):
                o=tr+4+i*48
                t=u32(f,o); stack=u64(f,o+24); n=u32(f,o+32); stack_rva=u32(f,o+36)
                if not stack or not n or n>128*1024*1024: continue
                blob=read_virtual(f,rs,stack,n)
                if blob is None and stack_rva and stack_rva<=size and n<=size-stack_rva:
                    blob=read_at(f,stack_rva,n)
                if blob and needle in blob: shared.append(t)
        print("THREAD_STACKS_REFERENCING_RSI="+",".join(hex(x) for x in shared))
        print(f"THREAD_STACK_REFERENCE_COUNT={len(shared)}")
        # rt_dispatch receives the guest memcpy wrapper's context address and reads +0x108/+0x138.
        dispatch=0x70070C1DE0
        dctx=read_virtual(f,rs,dispatch,0x180)
        print(f"DISPATCH_CONTEXT={dispatch:#x} captured={dctx is not None}")
        if dctx is not None:
            for off in (0,8,0x10,0xF0,0x108,0x138):
                value=struct.unpack_from("<Q",dctx,off)[0]
                print(f"DISPATCH+{off:03X}={value:#018x}")
            ptr=struct.unpack_from("<Q",dctx,0x138)[0]
            if 0x100000000<=ptr<0x800000000000:
                pctx=read_virtual(f,rs,ptr,0x100)
                print(f"DISPATCH_PLUS_138_TARGET={ptr:#x} captured={pctx is not None}")
                if pctx is not None:
                    print("DISPATCH_PLUS_138_TARGET_HEX="+pctx.hex())

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: probe_orbitals_memcpy_context.py dump.dmp")
    main(sys.argv[1])
