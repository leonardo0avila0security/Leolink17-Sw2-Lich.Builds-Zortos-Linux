#!/usr/bin/env python3
"""Extract the exception context, stack and caller window from an AMD64 minidump."""
import struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP=Path(sys.argv[1]); OUT=Path("orbitals_exception_analysis"); OUT.mkdir(exist_ok=True)
SIG=0x504D444D
def read(f,o,n):
    f.seek(o); b=f.read(n)
    if len(b)!=n: raise ValueError(f"short read at file offset {o:#x}")
    return b
def u32(f,o): return struct.unpack("<I",read(f,o,4))[0]
def u64(f,o): return struct.unpack("<Q",read(f,o,8))[0]
def get_streams(f,fs):
    if u32(f,0)!=SIG: raise ValueError("invalid MDMP signature")
    n,dr=u32(f,8),u32(f,12)
    if n>100000 or dr+n*12>fs: raise ValueError("bad stream directory")
    out={}
    for i in range(n):
        t,z,r=struct.unpack("<III",read(f,dr+i*12,12))
        if r<=fs and z<=fs-r: out[t]=(z,r)
    return out
def get_ranges(f,s,fs):
    out=[]
    if 9 in s:
        z,r=s[9]; n=u64(f,r); p=u64(f,r+8)
        if n>2000000 or 16+n*16>z: raise ValueError("bad Memory64List")
        for i in range(n):
            va,sz=struct.unpack("<QQ",read(f,r+16+i*16,16))
            if sz and p+sz<=fs: out.append((va,sz,p))
            p+=sz
    if 5 in s:
        z,r=s[5]; n=u32(f,r)
        if n<=2000000 and 4+n*16<=z:
            for i in range(n):
                va,sz,off=struct.unpack("<QII",read(f,r+4+i*16,16))
                if sz and off+sz<=fs: out.append((va,sz,off))
    return out
def readva(f,rs,va,n):
    for start,sz,off in rs:
        if start<=va and va+n<=start+sz: return read(f,off+va-start,n)
    return None
def module_list(f,s):
    if 4 not in s:return []
    z,r=s[4]; n=u32(f,r); out=[]
    for i in range(n):
        m=r+4+i*108; base=u64(f,m); size=u32(f,m+8); nr=u32(f,m+20)
        ln=u32(f,nr); name=read(f,nr+4,ln).decode("utf-16le","replace").rstrip("\0")
        out.append((base,size,name))
    return out
def disasm(md, data, address, limit=100):
    if not data:return ["<memory not captured>"]
    lines=[]
    for ins in md.disasm(data,address):
        lines.append(f"{ins.address:016X}: {ins.bytes.hex(' '):32s} {ins.mnemonic:8s} {ins.op_str}")
        if len(lines)>=limit:break
    return lines
with DMP.open("rb") as f:
    fs=DMP.stat().st_size; s=get_streams(f,fs); rs=get_ranges(f,s,fs); mods=module_list(f,s)
    lines=[f"dump={DMP.name}",f"file_size={fs}",f"streams={sorted(s)}",f"memory_ranges={len(rs)}"]
    for b,z,n in mods: lines.append(f"MODULE {b:#x}-{b+z:#x} {n}")
    if 6 not in s: raise SystemExit("ERROR: MINIDUMP_EXCEPTION_STREAM (type 6) absent")
    z,r=s[6]
    if z<168: raise SystemExit(f"ERROR: exception stream too short: {z}")
    tid=u32(f,r); code=u32(f,r+8); flags=u32(f,r+12); exaddr=u64(f,r+24); np=u32(f,r+32)
    info=[u64(f,r+40+i*8) for i in range(min(np,15))]
    crva=u32(f,r+160)
    lines += ["",f"EXCEPTION thread_id={tid:#x} code={code:#010x} flags={flags:#x} address={exaddr:#x}",
              f"parameters({np})="+", ".join(hex(x) for x in info),f"context_rva={crva:#x}"]
    if crva==0 or crva+256>fs: raise SystemExit("ERROR: exception context record unavailable")
    ctx=read(f,crva,256)
    regs={}
    names=["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]
    offsets=[120,128,136,144,152,160,168,176,184,192,200,208,216,224,232,240]
    for n,o in zip(names,offsets): regs[n]=struct.unpack_from("<Q",ctx,o)[0]
    regs["rip"]=struct.unpack_from("<Q",ctx,248)[0]
    lines.append("REGISTERS "+ " ".join(f"{k}={v:#018x}" for k,v in regs.items()))
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    rip=regs["rip"]; codebytes=readva(f,rs,rip,96)
    lines += ["","FAULTING INSTRUCTIONS:"]+disasm(md,codebytes,rip)
    rsp=regs["rsp"]; stack=readva(f,rs,rsp,0x800)
    lines += ["","STACK @ RSP (first 0x800 bytes):"]
    if stack:
        for off in range(0,len(stack),16):
            q=stack[off:off+16]
            lines.append(f"{rsp+off:016X}: "+q.hex(" "))
    else: lines.append(f"<stack memory not captured at {rsp:#x}>")
    lines += ["","REGISTER-POINTED MEMORY (first 0x80 bytes where captured):"]
    for k,v in regs.items():
        if v==0: continue
        b=readva(f,rs,v,0x80)
        if b:
            lines.append(f"[{k}] {v:#x}: {b[:0x80].hex(' ')}")
    lines += ["","STACK DISASSEMBLY AROUND RIP (if captured):"]
    # capture 0x100 bytes before and 0x180 after RIP, disassemble from RIP-0x40
    start=max(0,rip-0x40); blob=readva(f,rs,start,0x200)
    lines += disasm(md,blob,start,80)
    (OUT/"exception_context.txt").write_text("\n".join(lines),encoding="utf-8")
    print("\n".join(lines[:45]))
