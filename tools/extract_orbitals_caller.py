#!/usr/bin/env python3
import struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP = Path(sys.argv[1])
OUT = Path("caller_1B5A8FF0")
OUT.mkdir(exist_ok=True)
SIG=0x504D444D
def read(f,o,n):
    f.seek(o); b=f.read(n)
    if len(b)!=n: raise ValueError(f"short read at file offset {o:#x}")
    return b
def u32(f,o): return struct.unpack("<I",read(f,o,4))[0]
def u64(f,o): return struct.unpack("<Q",read(f,o,8))[0]
def streams(f,fs):
    if u32(f,0)!=SIG: raise ValueError("invalid MDMP signature")
    n,dr=u32(f,8),u32(f,12)
    if n>100000 or dr+n*12>fs: raise ValueError("bad stream directory")
    s={}
    for i in range(n):
        t,z,r=struct.unpack("<III",read(f,dr+i*12,12))
        if r<=fs and z<=fs-r:s[t]=(z,r)
    return s
def ranges(f,s,fs):
    out=[]
    if 9 in s:
        z,r=s[9]; n=u64(f,r); p=u64(f,r+8)
        if n>2000000 or 16+n*16>z: raise ValueError("bad Memory64List")
        for i in range(n):
            va,sz=struct.unpack("<QQ",read(f,r+16+i*16,16))
            if sz and p+sz<=fs:out.append((va,sz,p))
            p+=sz
    if 5 in s:
        z,r=s[5]; n=u32(f,r)
        if n<=2000000 and 4+n*16<=z:
            for i in range(n):
                va,sz,off=struct.unpack("<QII",read(f,r+4+i*16,16))
                if sz and off+sz<=fs:out.append((va,sz,off))
    return out
def module(f,s,fs):
    z,r=s[4]; n=u32(f,r)
    for i in range(n):
        m=r+4+i*108; base=u64(f,m); size=u32(f,m+8); nr=u32(f,m+20)
        ln=u32(f,nr)
        name=read(f,nr+4,ln).decode("utf-16le","replace").rstrip("\0")
        if name.lower().replace("/","\\").endswith("orbitalgame.dll"):return base,size,name
    raise ValueError("orbitalgame.dll not found")
with DMP.open("rb") as f:
    fs=DMP.stat().st_size; s=streams(f,fs); rs=ranges(f,s,fs); base,modsz,name=module(f,s,fs)
    rva=0x1B5A8FF0; va=base+rva; lo=max(base,va-0x800); hi=min(base+modsz,va+0x800)
    buf=bytearray(b"\xCC"*(hi-lo)); valid=bytearray(hi-lo)
    for start,n,off in rs:
        a=max(lo,start); b=min(hi,start+n)
        if a<b:
            chunk=read(f,off+a-start,b-a); buf[a-lo:b-lo]=chunk; valid[a-lo:b-lo]=b"\1"*(b-a)
(OUT/"caller.bin").write_bytes(buf)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
lines=[f"module={name}",f"imagebase={base:#x}",f"target_rva={rva:#x}",f"target_va={va:#x}",f"window=[{lo:#x},{hi:#x})",f"captured={sum(valid)}/{len(valid)} bytes","NOTE: disassembly is emitted only for contiguous captured bytes."]
i=0
while i<len(buf):
    if not valid[i]:
        j=i+1
        while j<len(buf) and not valid[j]:j+=1
        lines.append(f"{lo+i:016X}: <NOT CAPTURED: {j-i} bytes>")
        i=j; continue
    j=i+1
    while j<len(buf) and valid[j]:j+=1
    chunk=bytes(buf[i:j])
    for ins in md.disasm(chunk,lo+i):
        lines.append(f"{ins.address:016X}: {ins.bytes.hex(' '):32s} {ins.mnemonic:8s} {ins.op_str}")
    i=j
(OUT/"disassembly.txt").write_text("\n".join(lines),encoding="utf-8")
print("\n".join(lines[:14]))
