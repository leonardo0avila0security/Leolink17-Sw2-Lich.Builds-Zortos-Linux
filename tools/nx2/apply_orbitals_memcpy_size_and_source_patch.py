#!/usr/bin/env python3
"""Apply two version-locked Orbitals memcpy fixes to the analysis-data DLL.

1) Zero the guest stack local consumed as memcpy length if its conditional
   assignment is skipped.
2) Refresh the fallback hostfn descriptor's source pointer from guest x1.
No game preparation, recompilation, or regeneration is performed.
"""
from pathlib import Path
import argparse, hashlib, struct, uuid, zipfile

EXPECTED_SHA256 = "8678d073fdffc4f3d518f492dbc3428f7257dc1ebe8467bb85d87a6633d97cf4"
EXPECTED_PDB_GUID = "d75ffc7c-ee2d-e2ca-4c4c-44205044422e"
EXPECTED_PDB_AGE = 1
IMAGE_BASE = 0x180000000

SIZE_PATCH_RVA = 0x1B5A84B5
SIZE_PATCH_FILE = 0x1B5A78B5
SIZE_PATCH_ORIGINAL = bytes.fromhex("4c 8d b3 e0 fe ff ff")  # lea r14,[rbx-0x120]
SIZE_RETURN_RVA = 0x1B5A84BC

SOURCE_PATCH_RVA = 0x1B5A9385
SOURCE_PATCH_FILE = 0x1B5A8785
SOURCE_PATCH_ORIGINAL = bytes.fromhex("48 89 86 f0 00 00 00")  # mov [rsi+0xf0],rax
SOURCE_RETURN_RVA = 0x1B5A938C

CAVE_RVA = 0x1C7ED286
CAVE_FILE = 0x1C7EC686
CAVE_SIZE = 0x17A
SOURCE_TRAMP_OFFSET = 0x20

# Guard bytes proving the exact generated function/frame layout.
RBX_LOAD_RVA = 0x1B5A84AE
RBX_LOAD_BYTES = bytes.fromhex("48 8b 9e 00 01 00 00")  # mov rbx,[rsi+0x100]
SIZE_READ_RVA = 0x1B5A8E13
SIZE_READ_BYTES = bytes.fromhex("4c 63 83 68 ff ff ff")  # movsxd r8,dword [rbx-0x98]
SIZE_CONDITIONAL_STORE_RVA = 0x1B5A8BAD
SIZE_CONDITIONAL_STORE_BYTES = bytes.fromhex("4c 89 8b 68 ff ff ff")  # mov [rbx-0x98],r9

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def pe_codeview(data):
    if data[:2] != b"MZ":
        raise ValueError("Not a PE file (MZ missing)")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("PE signature missing")
    nsec = struct.unpack_from("<H", data, pe+6)[0]
    optsz = struct.unpack_from("<H", data, pe+20)[0]
    opt = pe+24
    if struct.unpack_from("<H", data, opt)[0] != 0x20b:
        raise ValueError("Expected PE32+")
    imagebase = struct.unpack_from("<Q", data, opt+24)[0]
    dd = opt+112
    debug_rva, debug_size = struct.unpack_from("<II", data, dd+6*8)
    sec_off = opt+optsz
    sections = []
    for i in range(nsec):
        o = sec_off+i*40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o+8)
        sections.append((va, max(vsize, rawsize), rawsize, rawptr))
    def rva_off(rva, length=1):
        for va, extent, rawsize, rawptr in sections:
            if va <= rva and rva+length <= va+extent:
                delta = rva-va
                if delta+length <= rawsize:
                    return rawptr+delta
        return None
    doff = rva_off(debug_rva, debug_size) if debug_rva else None
    if doff is None:
        raise ValueError("PE debug directory unavailable")
    for p in range(doff, doff+debug_size, 28):
        typ = struct.unpack_from("<I", data, p+12)[0]
        size = struct.unpack_from("<I", data, p+16)[0]
        ptr = struct.unpack_from("<I", data, p+24)[0]
        if typ == 2 and ptr and size >= 24 and data[ptr:ptr+4] == b"RSDS":
            guid = str(uuid.UUID(bytes_le=data[ptr+4:ptr+20]))
            age = struct.unpack_from("<I", data, ptr+20)[0]
            return imagebase, guid, age
    raise ValueError("RSDS CodeView record not found")

def rel32(src_rva, dst_rva):
    delta = dst_rva-(src_rva+5)
    if not -(1<<31) <= delta < (1<<31):
        raise ValueError("relative branch out of range")
    return struct.pack("<i", delta)

def apply(data):
    actual = sha256(data)
    if actual != EXPECTED_SHA256:
        raise ValueError(f"Wrong orbitalgame.dll SHA256 {actual}; expected {EXPECTED_SHA256}")
    imagebase, guid, age = pe_codeview(data)
    if imagebase != IMAGE_BASE:
        raise ValueError(f"Unexpected image base {imagebase:#x}")
    if guid.lower() != EXPECTED_PDB_GUID or age != EXPECTED_PDB_AGE:
        raise ValueError(f"PDB mismatch: {guid} age {age}")

    checks = (
        (RBX_LOAD_RVA-0xC00, RBX_LOAD_BYTES, "guest SP load"),
        (SIZE_PATCH_FILE, SIZE_PATCH_ORIGINAL, "size-local init insertion"),
        (SIZE_READ_RVA-0xC00, SIZE_READ_BYTES, "size-local read"),
        (SIZE_CONDITIONAL_STORE_RVA-0xC00, SIZE_CONDITIONAL_STORE_BYTES, "conditional size-local store"),
        (SOURCE_PATCH_FILE, SOURCE_PATCH_ORIGINAL, "fallback source patch"),
    )
    for off, expected, label in checks:
        if data[off:off+len(expected)] != expected:
            raise ValueError(f"{label}: original bytes mismatch at file offset {off:#x}")
    if data[CAVE_FILE:CAVE_FILE+CAVE_SIZE] != b"\xCC"*CAVE_SIZE:
        raise ValueError("Code cave is not intact INT3 padding")

    # Trampoline A: preserve the original LEA, then initialize the guest frame
    # local to zero. RBX already points at the pre-prologue guest SP here.
    size_cave = (
        SIZE_PATCH_ORIGINAL +
        bytes.fromhex("48 c7 83 68 ff ff ff 00 00 00 00") +
        b"\xE9" + rel32(CAVE_RVA+18, SIZE_RETURN_RVA)
    )
    # Trampoline B: preserve the original guest return-PC store and additionally
    # marshal current guest x1 (R9) into hostfn context +8.
    src_cave_rva = CAVE_RVA + SOURCE_TRAMP_OFFSET
    source_cave = (
        SOURCE_PATCH_ORIGINAL +
        bytes.fromhex("4c 89 4e 08") +
        b"\xE9" + rel32(src_cave_rva+11, SOURCE_RETURN_RVA)
    )
    if len(size_cave) != 23 or len(source_cave) != 16:
        raise AssertionError("Unexpected trampoline length")

    size_jump = b"\xE9" + rel32(SIZE_PATCH_RVA, CAVE_RVA) + b"\x90\x90"
    source_jump = b"\xE9" + rel32(SOURCE_PATCH_RVA, src_cave_rva) + b"\x90\x90"

    out = bytearray(data)
    out[SIZE_PATCH_FILE:SIZE_PATCH_FILE+7] = size_jump
    out[SOURCE_PATCH_FILE:SOURCE_PATCH_FILE+7] = source_jump
    out[CAVE_FILE:CAVE_FILE+len(size_cave)] = size_cave
    so = CAVE_FILE+SOURCE_TRAMP_OFFSET
    out[so:so+len(source_cave)] = source_cave

    # Byte-for-byte postconditions, including the original instructions in
    # both trampolines and both jump-back destinations.
    if out[SIZE_PATCH_FILE:SIZE_PATCH_FILE+7] != size_jump:
        raise AssertionError("size patch-site verification failed")
    if out[SOURCE_PATCH_FILE:SOURCE_PATCH_FILE+7] != source_jump:
        raise AssertionError("source patch-site verification failed")
    if out[CAVE_FILE:CAVE_FILE+len(size_cave)] != size_cave:
        raise AssertionError("size trampoline verification failed")
    if out[so:so+len(source_cave)] != source_cave:
        raise AssertionError("source trampoline verification failed")

    report = {
        "original_sha256": actual,
        "patched_sha256": sha256(out),
        "pdb_guid": guid,
        "pdb_age": str(age),
        "size_patch_rva": hex(SIZE_PATCH_RVA),
        "size_patch_file_offset": hex(SIZE_PATCH_FILE),
        "size_patch_original": SIZE_PATCH_ORIGINAL.hex(" "),
        "size_patch_bytes": size_jump.hex(" "),
        "size_trampoline": size_cave.hex(" "),
        "size_trampoline_semantics": "preserve lea r14,[rbx-0x120]; mov qword ptr [rbx-0x98],0; jump back",
        "size_read_rva": hex(SIZE_READ_RVA),
        "size_conditional_store_rva": hex(SIZE_CONDITIONAL_STORE_RVA),
        "source_patch_rva": hex(SOURCE_PATCH_RVA),
        "source_patch_file_offset": hex(SOURCE_PATCH_FILE),
        "source_patch_bytes": source_jump.hex(" "),
        "source_trampoline": source_cave.hex(" "),
        "source_trampoline_semantics": "preserve mov [rsi+0xf0],rax; mov [rsi+8],r9; jump back",
        "cave_rva": hex(CAVE_RVA),
        "source_trampoline_rva": hex(src_cave_rva),
        "change": "initialize size local to zero and marshal fallback guest x1 source pointer",
        "status": "candidate binary patch; requires runtime/gameplay validation",
    }
    return bytes(out), report

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="orbitalgame.dll or orbitals-recomp.zip")
    ap.add_argument("-o", "--output", default="orbitalgame.dll")
    args = ap.parse_args()
    src = Path(args.input)
    if src.suffix.lower() == ".zip":
        with zipfile.ZipFile(src) as z:
            name = next((n for n in z.namelist() if Path(n).name.lower() == "orbitalgame.dll"), None)
            if not name:
                raise SystemExit("orbitalgame.dll not found in input ZIP")
            data = z.read(name)
    else:
        data = src.read_bytes()
    patched, report = apply(data)
    out = Path(args.output)
    out.write_bytes(patched)
    text = "ORBITALS MEMCPY SIZE + SOURCE PATCH\n\n" + "\n".join(f"{k}={v}" for k,v in report.items()) + "\n"
    Path(str(out)+".patch-report.txt").write_text(text, encoding="utf-8")
    print(text)
    print(f"PATCHED_DLL={out.resolve()}")

if __name__ == "__main__":
    main()
