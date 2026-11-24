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
    for label,address,length in CHECKS:
        print(f"\n[{label}] address={address:#x} length={length:#x} end={address+length:#x}")
        hits=[r for r in regions if r[0]<=address<r[0]+r[1]]
        if not hits:
            print("NO MEMORY-INFO REGION CONTAINS ADDRESS")
            continue
        for base,sz,state,prot,typ,ab,ap in hits:
            fits=address+length<=base+sz
            print(f"region={base:#x}+{sz:#x} end={base+sz:#x} state={state:#x} protect={prot:#x} type={typ:#x} allocation={ab:#x} alloc_protect={ap:#x}")
            print(f"entire_span_in_region={fits} committed={state==0x1000} readable={(prot & 0xFF) in (0x02,0x04,0x08,0x20,0x40,0x80)}")
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: check_orbitals_memcpy_regions.py dump.dmp")
    main(sys.argv[1])
