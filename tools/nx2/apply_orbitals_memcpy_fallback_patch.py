#!/usr/bin/env python3
"""Apply the verified, minimal Orbitals memcpy fallback argument-store patch.

The patch is version-locked to the orbitalgame.dll shipped in release tag
analysis-data. It does not rebuild or regenerate the game.
"""
from pathlib import Path
import argparse, hashlib, struct, uuid, zipfile

EXPECTED_SHA256 = "8678d073fdffc4f3d518f492dbc3428f7257dc1ebe8467bb85d87a6633d97cf4"
EXPECTED_PDB_GUID = "d75ffc7c-ee2d-e2ca-4c4c-44205044422e"
EXPECTED_PDB_AGE = 1
PATCH_RVA = 0x1B5A9385
PATCH_FILE_OFFSET = 0x1B5A8785
PATCH_ORIGINAL = bytes.fromhex("48 89 86 f0 00 00 00")
CAVE_RVA = 0x1C7ED286
CAVE_FILE_OFFSET = 0x1C7EC686
CAVE_SIZE = 0x17A
RETURN_RVA = 0x1B5A938C
IMAGE_BASE = 0x180000000

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def pe_codeview(data):
    if data[:2] != b"MZ": raise ValueError("Not a PE file (MZ missing)")
    pe=struct.unpack_from("<I",data,0x3c)[0]
    if data[pe:pe+4] != b"PE\0\0": raise ValueError("PE signature missing")
    nsec=struct.unpack_from("<H",data,pe+6)[0]
    optsz=struct.unpack_from("<H",data,pe+20)[0]
    opt=pe+24
    if struct.unpack_from("<H",data,opt)[0] != 0x20b: raise ValueError("Expected PE32+")
    imagebase=struct.unpack_from("<Q",data,opt+24)[0]
    dd=opt+112
    debug_rva,debug_size=struct.unpack_from("<II",data,dd+6*8)
    sec_off=opt+optsz
    sections=[]
    for i in range(nsec):
        o=sec_off+i*40
        name=data[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
        vsize,va,rawsize,rawptr=struct.unpack_from("<IIII",data,o+8)
        flags=struct.unpack_from("<I",data,o+36)[0]
        sections.append((name,vsize,va,rawsize,rawptr,flags))
    def rva_off(rva,length=1):
        for name,vsize,va,rawsize,rawptr,flags in sections:
            if va<=rva and rva+length<=va+max(vsize,rawsize):
                delta=rva-va
                if delta+length<=rawsize:return rawptr+delta
        return None
    doff=rva_off(debug_rva,debug_size) if debug_rva else None
    if doff is None: raise ValueError("PE debug directory unavailable")
    for p in range(doff,doff+debug_size,28):
        typ=struct.unpack_from("<I",data,p+12)[0]
        size=struct.unpack_from("<I",data,p+16)[0]
        ptr=struct.unpack_from("<I",data,p+24)[0]
        if typ==2 and ptr and size>=24 and data[ptr:ptr+4]==b"RSDS":
            guid=str(uuid.UUID(bytes_le=data[ptr+4:ptr+20]))
            age=struct.unpack_from("<I",data,ptr+20)[0]
            return imagebase,guid,age,sections
    raise ValueError("RSDS CodeView record not found")

def rel32(src_rva, dst_rva):
    delta=dst_rva-(src_rva+5)
    if not -(1<<31)<=delta<(1<<31): raise ValueError("relative branch out of range")
    return struct.pack("<i",delta)

def apply(data):
    actual=sha256(data)
    if actual != EXPECTED_SHA256:
        raise ValueError(f"Wrong orbitalgame.dll build: SHA256 {actual}; expected {EXPECTED_SHA256}")
    imagebase,guid,age,sections=pe_codeview(data)
    if imagebase != IMAGE_BASE: raise ValueError(f"Unexpected image base {imagebase:#x}")
    if guid.lower()!=EXPECTED_PDB_GUID or age!=EXPECTED_PDB_AGE:
        raise ValueError(f"PDB mismatch: {guid} age {age}")
    if data[PATCH_FILE_OFFSET:PATCH_FILE_OFFSET+7] != PATCH_ORIGINAL:
        raise ValueError("Patch-site bytes do not match expected original instruction")
    if data[CAVE_FILE_OFFSET:CAVE_FILE_OFFSET+CAVE_SIZE] != b"\xCC"*CAVE_SIZE:
        raise ValueError("Code cave is not intact INT3 padding")

    # Relocate the original return-PC store, add the missing x1/source store,
    # then return to the untouched destination-store instruction. The original
    # wrapper CALL remains at its original address and retains its return PC.
    cave = (
        bytes.fromhex("48 89 86 f0 00 00 00") +  # mov [rsi+0xf0], rax
        bytes.fromhex("4c 89 4e 08") +           # mov [rsi+8], r9 (guest x1)
        b"\xE9" + rel32(CAVE_RVA+11, RETURN_RVA)
    )
    if len(cave)!=16: raise AssertionError("Unexpected trampoline length")
    patch = b"\xE9" + rel32(PATCH_RVA,CAVE_RVA) + b"\x90\x90"
    out=bytearray(data)
    out[PATCH_FILE_OFFSET:PATCH_FILE_OFFSET+7]=patch
    out[CAVE_FILE_OFFSET:CAVE_FILE_OFFSET+len(cave)]=cave

    if out[PATCH_FILE_OFFSET:PATCH_FILE_OFFSET+7] != patch: raise AssertionError("Patch-site verification failed")
    if out[CAVE_FILE_OFFSET:CAVE_FILE_OFFSET+len(cave)] != cave: raise AssertionError("Cave verification failed")
    return bytes(out), {
        "original_sha256":actual,
        "patched_sha256":sha256(out),
        "pdb_guid":guid,
        "pdb_age":str(age),
        "patch_rva":hex(PATCH_RVA),
        "patch_file_offset":hex(PATCH_FILE_OFFSET),
        "cave_rva":hex(CAVE_RVA),
        "cave_file_offset":hex(CAVE_FILE_OFFSET),
        "return_rva":hex(RETURN_RVA),
        "patch_bytes":patch.hex(" "),
        "cave_bytes":cave.hex(" "),
        "change":"store current guest x1/r9 into hostfn descriptor [rsi+8] before memcpy dispatch",
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("input",help="orbitalgame.dll or orbitals-recomp.zip")
    ap.add_argument("-o","--output",default="orbitalgame.dll",help="patched DLL output path")
    args=ap.parse_args()
    src=Path(args.input)
    if src.suffix.lower()==".zip":
        with zipfile.ZipFile(src) as z:
            name=next((n for n in z.namelist() if Path(n).name.lower()=="orbitalgame.dll"),None)
            if not name: raise SystemExit("orbitalgame.dll not found in input ZIP")
            data=z.read(name)
    else:
        data=src.read_bytes()
    patched,report=apply(data)
    out=Path(args.output)
    out.write_bytes(patched)
    text="ORBITALS MEMCPY FALLBACK PATCH\n\n"+"\n".join(f"{k}={v}" for k,v in report.items())+"\n"
    Path(str(out)+".patch-report.txt").write_text(text,encoding="utf-8")
    print(text)
    print(f"PATCHED_DLL={out.resolve()}")
if __name__=="__main__": main()
