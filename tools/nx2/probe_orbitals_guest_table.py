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
        def overlap_values(addr,length=8):
            hits=[r for r in ranges if r[0]<=addr and addr+length<=r[0]+r[1]]
            vals=[]
            for s,l,o in hits:
                f.seek(o+addr-s); raw=f.read(length)
                if len(raw)==length:
                    vals.append((s,l,o,int.from_bytes(raw,"little")))
            return vals
        def show_overlaps(label,addr):
            vals=overlap_values(addr)
            print(f"\\n[{label}] address={addr:#x} overlapping_ranges={len(vals)}")
            for s,l,o,v in vals:
                print(f"range={s:#x}+{l:#x} file_offset={o+(addr-s):#x} value={v:#018x}")
            if vals:
                chosen=max(vals,key=lambda x:x[0]+x[1])
                print(f"readv_selected={chosen[3]:#018x} by max-end rule")
        x21_guest=0x0E40012810
        x27=0xCE01F2C00
        show_overlaps("x21_plus_0x158",x21_guest+0x158)
        show_overlaps("x27_plus_0xD0",x27+0xD0)
        show_overlaps("x27_plus_0xD8",x27+0xD8)
        show_overlaps("d0_load_address",x27-0xB8)
        print(f"\\n[REGISTER-CHAIN CANDIDATE] x21={x21_guest:#x} x27={x27:#x}")
        print(f"x27_minus_x21base={(x27-0xCE01F2C00):#x}; expected w20=0 if [x21+0x158] resolves to x27")
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
