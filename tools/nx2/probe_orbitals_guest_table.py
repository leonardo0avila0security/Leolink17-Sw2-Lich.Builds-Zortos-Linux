#!/usr/bin/env python3
"""Reconstruct the guest x27 table entry and the d0 load feeding memcpy size."""
import mmap,struct,sys

def parse(f):
    f.seek(0,2); size=f.tell(); f.seek(0)
    if f.read(4)!=b"MDMP": raise ValueError("not MDMP")
    f.seek(8); n=struct.unpack("<I",f.read(4))[0]; drva=struct.unpack("<I",f.read(4))[0]
    streams={}
    for i in range(n):
        f.seek(drva+i*12); typ,sz,rva=struct.unpack("<III",f.read(12)); streams[typ]=(sz,rva)
    ranges=[]
    if 9 in streams:
        sz,rva=streams[9]; f.seek(rva); count,cur=struct.unpack("<QQ",f.read(16))
        for _ in range(count):
            va,length=struct.unpack("<QQ",f.read(16)); ranges.append((va,length,cur));cur+=length
    if 5 in streams:
        sz,rva=streams[5]; f.seek(rva); count=struct.unpack("<I",f.read(4))[0]
        for _ in range(count):
            va,length,fo=struct.unpack("<QII",f.read(16))
            if length:ranges.append((va,length,fo))
    return sorted(ranges),size

def readv(f,ranges,addr,n):
    out=bytearray();cur=addr;end=addr+n
    while cur<end:
        candidates=[r for r in ranges if r[0]<=cur<r[0]+r[1]]
        if not candidates:return None
        s,l,o=max(candidates,key=lambda x:x[0]+x[1])
        take=min(end,s+l)-cur
        f.seek(o+cur-s);b=f.read(take)
        if len(b)!=take:return None
        out.extend(b);cur+=take
    return bytes(out)

def q(data,o): return struct.unpack_from("<Q",data,o)[0]
def s32(v): return struct.unpack("<i",struct.pack("<I",v&0xffffffff))[0]

def main(path):
    with open(path,"rb") as f:
        ranges,fsz=parse(f)
        print(f"dump_size={fsz:,} memory_ranges={len(ranges)}")
        x21=0xCE01F2C00
        x21obj=readv(f,ranges,x21,0x220)
        print(f"\n[X21 CANDIDATE] {x21:#x} captured={x21obj is not None}")
        if x21obj:
            for off in (0xD0,0xD8,0x120,0x158,0x410):
                print(f"x21+{off:#x} qword={q(x21obj,off) if off+8<=len(x21obj) else 'outside'}")
        table=0x0E40012810
        print(f"\\n[TABLE] base={table:#x} stride=0xE8; probing each entry separately")
        matches=[]
        for idx in range(4096):
            rec_addr=table+idx*0xE8
            rec=readv(f,ranges,rec_addr,0xE0)
            if rec is None:
                if idx<12: print(f"idx={idx:3d} x27={rec_addr:#x} NOT_CAPTURED")
                continue
            raw=q(rec,0xD8)
            count=s32(raw)
            x21_base=q(x21obj,0x158) if x21obj else 0
            base=x21_base if x21_base else rec_addr+0x10
            x8=(base+(count<<6))&0xffffffffffffffff
            load_addr=(x8-8)&0xffffffffffffffff
            loaded=readv(f,ranges,load_addr,8)
            val=q(loaded,0) if loaded else None
            if raw or val is not None:
                print(f"idx={idx:3d} x27={rec_addr:#x} +D8raw={raw:#018x} s32={count} x21_plus_158={x21_base:#x} base={base:#x} x8-8={load_addr:#x} d0={('unmapped' if val is None else hex(val))}")
            if (val is not None and (val&0xffffffff)==0x01490140) or (raw&0xffffffff)==0x01490140:
                matches.append((idx,rec_addr,raw,base,x8,load_addr,0 if val is None else val))
        print(f"\\nMATCHES_LOW32_01490140={len(matches)}")
        for x in matches: print("MATCH "+ " ".join(hex(v) if isinstance(v,int) else str(v) for v in x))
        x21_guest=0x0E40012810
        x27=0xCE01F2C00
        x21p158_data=readv(f,ranges,x21_guest+0x158,8)
        x21p158=q(x21p158_data,0) if x21p158_data else None
        x27d0_data=readv(f,ranges,x27+0xD0,8)
        x27d8_data=readv(f,ranges,x27+0xD8,8)
        x27d0=q(x27d0_data,0) if x27d0_data else None
        x27d8=q(x27d8_data,0) if x27d8_data else None
        w8=s32(x27d8) if x27d8 is not None else None
        selected=(x27d0 if x27d0 else x27+0x10) if x27d0 is not None else None
        x8=((selected+(w8<<6))&0xffffffffffffffff) if selected is not None else None
        load_addr=((x8-8)&0xffffffffffffffff) if x8 is not None else None
        loaded=readv(f,ranges,load_addr,8) if load_addr is not None else None
        d0=q(loaded,0) if loaded else None
        print("\\n[EXACT GUEST x27 / SIZE LOAD RECONSTRUCTION]")
        print(f"x21={x21_guest:#x} x21+0x158={None if x21p158 is None else hex(x21p158)}")
        print(f"x27={x27:#x} index={(x27-x21p158)//0xE8 if x21p158 is not None and x27>=x21p158 else 'base-mismatch'}")
        print(f"x27+0xD0={None if x27d0 is None else hex(x27d0)} x27+0xD8={None if x27d8 is None else hex(x27d8)} signed_w8={w8}")
        print(f"selected_base={None if selected is None else hex(selected)} x8={None if x8 is None else hex(x8)} load_d0_at={None if load_addr is None else hex(load_addr)} d0={None if d0 is None else hex(d0)}")
        if d0 is not None:
            count=s32(d0)
            print(f"x25_signed={count:#x} x2_size={(count*4)&0xffffffffffffffff:#x}")
        for label,addr,n in (("source_stack_object",0x11C51F8A8,0x200),("string_object",0x11C51F6F0,0x100),("x21_preceding",x21-0x200,0x420)):
            data=readv(f,ranges,addr,n)
            print(f"\n[{label}] {addr:#x} captured={data is not None} length={0 if data is None else len(data):#x}")
            if data:
                for off in range(0,len(data)-7,8):
                    v=q(data,off)
                    if off<0x100 or v in (0x01460149013D0140,0x0000000001490140,0x11C51F8A8,0xCE01F2C00):
                        print(f"+{off:03x} {v:016x}")
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: probe_orbitals_guest_table.py dump.dmp")
    main(sys.argv[1])
