#!/usr/bin/env python3
"""Recover the exact selected 0xE8 guest record and the x8-8 metadata load.

Read-only analysis of the matching 16952 minidump. It reconstructs x21 from
f_7001759b20's saved callee register, follows [x21+0x158] to the record array,
and evaluates the exact AArch64 address calculation at main+0x1759e2c.
"""
import struct, sys

def parse(f):
    f.seek(0, 2); file_size=f.tell(); f.seek(0)
    if f.read(4) != b"MDMP": raise ValueError("not an MDMP dump")
    f.seek(8); n=struct.unpack("<I",f.read(4))[0]; directory=struct.unpack("<I",f.read(4))[0]
    streams={}
    for i in range(n):
        f.seek(directory+i*12)
        typ,size,rva=struct.unpack("<III",f.read(12)); streams[typ]=(size,rva)
    ranges=[]
    if 9 in streams:
        size,rva=streams[9]; f.seek(rva); count,pos=struct.unpack("<QQ",f.read(16))
        for _ in range(count):
            va,length=struct.unpack("<QQ",f.read(16))
            if length and pos+length<=file_size: ranges.append((va,length,pos))
            pos+=length
    if 5 in streams:
        size,rva=streams[5]; f.seek(rva); count=struct.unpack("<I",f.read(4))[0]
        for _ in range(count):
            va,length,fo=struct.unpack("<QII",f.read(16))
            if length and fo+length<=file_size: ranges.append((va,length,fo))
    return sorted(ranges),file_size

def readv(f,ranges,address,length):
    out=bytearray(); pos=address; end=address+length
    while pos<end:
        covering=[r for r in ranges if r[0]<=pos<r[0]+r[1]]
        if not covering: return None
        base,size,filepos=max(covering,key=lambda r:r[0]+r[1])
        take=min(end,base+size)-pos
        f.seek(filepos+pos-base); chunk=f.read(take)
        if len(chunk)!=take:return None
        out.extend(chunk);pos+=take
    return bytes(out)

def u32(data,off=0): return struct.unpack_from("<I",data,off)[0]
def u64(data,off=0): return struct.unpack_from("<Q",data,off)[0]
def s32(v): return struct.unpack("<i",struct.pack("<I",v&0xffffffff))[0]
def qread(f,ranges,addr):
    b=readv(f,ranges,addr,8); return None if b is None else u64(b)

def main(path):
    with open(path,"rb") as f:
        ranges,file_size=parse(f)
        # context+0x100 is the guest SP before the 0x120-byte frame allocation.
        # The prologue stores x21 at active_sp+0x108 = frame_base-0x18.
        context_addr=None
        # Locate the known faulting descriptor through the exception context RSI.
        # ExceptionStream type 6; ThreadContext descriptor is at stream +160/+164.
        n=struct.unpack_from("<I",readv(f,ranges,0,0) or b"\0"*4)[0] if False else 0
        f.seek(8); count=struct.unpack("<I",f.read(4))[0]; directory=struct.unpack("<I",f.read(4))[0]
        streams={}
        for i in range(count):
            f.seek(directory+i*12); typ,size,rva=struct.unpack("<III",f.read(12)); streams[typ]=(size,rva)
        if 6 not in streams: raise SystemExit("ExceptionStream missing")
        size,rva=streams[6]
        f.seek(rva+164); ctx_rva=struct.unpack("<I",f.read(4))[0]
        f.seek(ctx_rva+168); rsi=struct.unpack("<Q",f.read(8))[0]
        descriptor=readv(f,ranges,rsi,0x400)
        if descriptor is None: raise SystemExit("fault descriptor not captured")
        frame_base=u64(descriptor,0x100)
        active_sp=frame_base-0x120
        saved_x21=qread(f,ranges,active_sp+0x108)
        print(f"dump_size={file_size} memory_ranges={len(ranges)}")
        print(f"fault_context={rsi:#x} guest_frame_base={frame_base:#x} active_sp={active_sp:#x}")
        print(f"saved_x21={saved_x21 if saved_x21 is not None else 'not-captured'}")
        if saved_x21 is None: raise SystemExit("saved x21 not captured")
        array_ptr=qread(f,ranges,saved_x21+0x158)
        count_data=readv(f,ranges,saved_x21+0x160,4)
        max_records=u32(count_data) if count_data else None
        print(f"x21_plus_158_array_ptr={array_ptr if array_ptr is not None else 'not-captured'}")
        print(f"x21_plus_160_record_limit={max_records if max_records is not None else 'not-captured'}")
        if array_ptr is None or max_records is None: raise SystemExit("record array metadata unavailable")
        # Bound scan defensively; the dump's own count is authoritative.
        scan_count=min(max_records,100000)
        matches=[]
        for index in range(scan_count):
            record=array_ptr+index*0xE8
            raw=readv(f,ranges,record,0xE0)
            if raw is None: continue
            field_d0=u64(raw,0xD0)
            field_d8=u32(raw,0xD8)
            signed_index=s32(field_d8)
            base=field_d0 if field_d0 else record+0x10
            x8=(base+(signed_index<<6))&0xffffffffffffffff
            loaded=readv(f,ranges,x8-8,8)
            if loaded is None: continue
            d0=u64(loaded)
            if (d0&0xffffffff)==0x01490140:
                matches.append((index,record,field_d0,field_d8,base,x8,d0))
        print(f"scanned_records={scan_count} matching_low32_01490140={len(matches)}")
        for index,record,field_d0,field_d8,base,x8,d0 in matches:
            print(f"MATCH index={index} record={record:#x} field_d0={field_d0:#x} field_d8={field_d8:#x} signed_d8={s32(field_d8)} base={base:#x} x8={x8:#x} [x8-8]={d0:#018x}")
            for label,addr,length in (("record",record,0xE8),("x8_neighborhood",max(0,x8-0x50),0x90)):
                blob=readv(f,ranges,addr,length)
                print(f"{label}_addr={addr:#x} captured={blob is not None}")
                if blob:
                    for off in range(0,len(blob)-7,8):
                        print(f"  {label}+{off:#04x}={u64(blob,off):#018x}")
        # Also show the stack locals that hold the copied d0 and selected source.
        for off in (0x20,0x38,0x80,0x88,0x90,0x98,0xA0,0xA8,0xB0,0xB8,0xC0,0xC8,0xD0):
            value=qread(f,ranges,active_sp+off)
            print(f"stack+{off:#04x}={value if value is not None else 'not-captured'}")
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: probe_orbitals_size_field.py dump.dmp")
    main(sys.argv[1])
