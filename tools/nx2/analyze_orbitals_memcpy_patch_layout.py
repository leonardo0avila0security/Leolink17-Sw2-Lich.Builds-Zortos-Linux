#!/usr/bin/env python3
"""Read-only PE layout inspection for the Orbitals memcpy fallback patch."""
from pathlib import Path
import hashlib, struct, sys, zipfile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TARGET_DLL_RVA = 0x1B5A937E
TARGET_EXE_RVA = 0x40CE0
EXECUTE = 0x20000000

def pe_info(data, label):
    if data[:2] != b"MZ": raise ValueError(f"{label}: missing MZ")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe+4] != b"PE\0\0": raise ValueError(f"{label}: missing PE")
    machine, nsec, ts, symptr, nsyms, optsz, chars = struct.unpack_from("<HHIIIHH", data, pe+4)
    opt = pe+24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20b: raise ValueError(f"{label}: expected PE32+ optional header, got {magic:#x}")
    imagebase = struct.unpack_from("<Q", data, opt+24)[0]
    dd_off = opt+112
    debug_rva, debug_size = struct.unpack_from("<II", data, dd_off+6*8)
    sec_off = opt+optsz
    sections=[]
    for i in range(nsec):
        o=sec_off+i*40
        name=data[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII",data,o+8)
        flags=struct.unpack_from("<I",data,o+36)[0]
        sections.append(dict(name=name,va=va,vsize=vsize,rawsize=rawsize,rawptr=rawptr,flags=flags))
    def rva_off(rva, length=1):
        for s in sections:
            extent=max(s["vsize"],s["rawsize"])
            if s["va"] <= rva and rva+length <= s["va"]+extent:
                delta=rva-s["va"]
                if delta+length > s["rawsize"]: return None
                return s["rawptr"]+delta
        return None
    return dict(pe=pe,machine=machine,nsec=nsec,timestamp=ts,imagebase=imagebase,
                debug_rva=debug_rva,debug_size=debug_size,sections=sections,rva_off=rva_off)

def codeview(data, info):
    if not info["debug_rva"]: return "CodeView: no debug directory"
    off=info["rva_off"](info["debug_rva"],info["debug_size"])
    if off is None: return "CodeView: debug directory not raw-backed"
    for p in range(off,off+info["debug_size"],28):
        if p+28>len(data): break
        typ=struct.unpack_from("<I",data,p+12)[0]
        size,ptr=struct.unpack_from("<II",data,p+16)[0],struct.unpack_from("<I",data,p+24)[0]
        if typ==2 and ptr and size>=24 and data[ptr:ptr+4]==b"RSDS":
            import uuid
            guid=uuid.UUID(bytes_le=data[ptr+4:ptr+20])
            age=struct.unpack_from("<I",data,ptr+20)[0]
            pdb=data[ptr+24:ptr+size].split(b"\0",1)[0].decode("utf8","replace")
            return f"CodeView: GUID={guid} age={age} pdb={pdb}"
    return "CodeView: RSDS record not found"

def disasm_window(data, info, rva, size, label):
    off=info["rva_off"](rva,size)
    if off is None:
        print(f"{label}: RVA {rva:#x} not raw-backed")
        return
    blob=data[off:off+size]
    print(f"\n[{label}] RVA={rva:#x} file_offset={off:#x} VA={info['imagebase']+rva:#x}")
    print("BYTES="+blob.hex(" "))
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    for ins in md.disasm(blob,info["imagebase"]+rva):
        print(f"{ins.address-info['imagebase']:08x}: {ins.mnemonic:8} {ins.op_str}")

def caves(data, info, minimum=24):
    found=[]
    for s in info["sections"]:
        if not (s["flags"] & EXECUTE): continue
        raw=data[s["rawptr"]:s["rawptr"]+s["rawsize"]]
        for byte,label,minlen in ((0xCC,"INT3",minimum),(0x90,"NOP",minimum)):
            i=0
            while i<len(raw):
                if raw[i]!=byte: i+=1; continue
                j=i+1
                while j<len(raw) and raw[j]==byte: j+=1
                if j-i>=minlen:
                    found.append((j-i,s["va"]+i,s["rawptr"]+i,label,s["name"]))
                i=j
    found.sort(reverse=True)
    for length,rva,off,label,section in found[:80]:
        print(f"CAVE {label:4} len={length:#x} {section} RVA={rva:#x} file={off:#x}")

def main(path):
    out=Path("patch-layout-report.txt")
    lines=[]
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        dll_name=next((n for n in names if Path(n).name.lower()=="orbitalgame.dll"),None)
        exe_name=next((n for n in names if Path(n).name.lower()=="orbitals-recomp.exe"),None)
        if not dll_name or not exe_name:
            raise SystemExit(f"Required binaries not found. dll={dll_name} exe={exe_name}; entries={len(names)}")
        for name,label,rva in ((dll_name,"orbitalgame.dll",TARGET_DLL_RVA),(exe_name,"orbitals-recomp.exe",TARGET_EXE_RVA)):
            data=z.read(name)
            info=pe_info(data,label)
            print(f"\n===== {label} =====")
            print(f"archive_member={name} size={len(data):,} sha256={hashlib.sha256(data).hexdigest()}")
            print(f"imagebase={info['imagebase']:#x} sections={info['nsec']} machine={info['machine']:#x}")
            print(codeview(data,info))
            for s in info["sections"]:
                if s["flags"] & EXECUTE:
                    print(f"EXEC_SECTION {s['name']} RVA={s['va']:#x} VSIZE={s['vsize']:#x} RAW={s['rawptr']:#x}+{s['rawsize']:#x}")
            disasm_window(data,info,rva,0x60 if label=="orbitalgame.dll" else 0x180,label+" target")
            if label=="orbitalgame.dll":
                caves(data,info)
    print("\nRead-only inspection only; no binary was modified.")
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: script orbitals-recomp.zip")
    main(sys.argv[1])
