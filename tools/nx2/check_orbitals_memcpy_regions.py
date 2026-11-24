#!/usr/bin/env python3
"""Check whether the reconstructed memcpy source/destination spans are mapped."""
import struct,sys

MAGIC=b"MDMP"
CHECKS=[
 ("expected_source",0x11C51F8A8,0x05240500),
 ("destination",0x12E1A8000C,0x05240500),
 ("bad_source",0x01460149013D0140,0x20),
]
def main(path):
    with open(path,"rb") as f:
        data=f.read()
    if data[:4]!=MAGIC: raise SystemExit("not a minidump")
    n=struct.unpack_from("<I",data,8)[0]; drva=struct.unpack_from("<I",data,12)[0]
    streams={}
    for i in range(n):
        typ,size,rva=struct.unpack_from("<III",data,drva+i*12)
        streams[typ]=(rva,size)
    if 16 not in streams: raise SystemExit("MemoryInfoListStream (16) absent")
    rva,size=streams[16]
    header,entry,count=struct.unpack_from("<IIQ",data,rva)
    regions=[]
    for i in range(count):
        o=rva+header+i*entry
        base,allocbase,allocprot=struct.unpack_from("<QQI",data,o)
        region_size=struct.unpack_from("<Q",data,o+24)[0]
        state,protect,typ=struct.unpack_from("<III",data,o+32)
        if region_size: regions.append((base,region_size,state,protect,typ,allocbase,allocprot))
    print(f"MemoryInfoList entries={count} header={header:#x} entry={entry:#x}")
    regions.sort(key=lambda r:r[0])
    for label,address,length in CHECKS:
        end=address+length
        print(f"\\n[{label}] address={address:#x} length={length:#x} end={end:#x}")
        hits=[r for r in regions if r[0]<=address<r[0]+r[1]]
        if not hits:
            print("NO MEMORY-INFO REGION CONTAINS ADDRESS")
            continue
        for base,sz,state,prot,typ,ab,ap in hits:
            print(f"start_region={base:#x}+{sz:#x} end={base+sz:#x} state={state:#x} protect={prot:#x} type={typ:#x} allocation={ab:#x} alloc_protect={ap:#x}")
        cur=address
        segments=0
        while cur<end:
            covering=[r for r in regions if r[0]<=cur<r[0]+r[1]]
            if not covering:
                print(f"COVERAGE_GAP at {cur:#x}; covered={cur-address:#x}/{length:#x}")
                break
            region=max(covering,key=lambda r:r[0]+r[1])
            base,sz,state,prot,typ,ab,ap=region
            seg_end=min(end,base+sz)
            readable=(prot & 0xFF) in (0x02,0x04,0x08,0x20,0x40,0x80)
            print(f"segment {segments}: {cur:#x}-{seg_end:#x} state={state:#x} protect={prot:#x} readable={readable}")
            if state!=0x1000 or not readable:
                print(f"UNREADABLE_OR_UNCOMMITTED at {cur:#x}; covered={cur-address:#x}/{length:#x}")
                break
            cur=seg_end
            segments+=1
        else:
            print(f"FULL_SPAN_COMMITTED_READABLE segments={segments}")
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: check_orbitals_memcpy_regions.py dump.dmp")
    main(sys.argv[1])
