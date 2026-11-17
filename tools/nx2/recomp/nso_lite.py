#!/usr/bin/env python3
# NSO reader without numpy (the probe and the analyzer ship as Windows executables).
# Decompresses an NSO's segments and reads its exported symbol table.
#   nso_lite.py <nso> [substring]   lists exported symbols (offset, size, name)
import struct
import sys

DT_NULL, DT_STRTAB, DT_SYMTAB = 0, 5, 6


def lz4_block_decompress(src: bytes, out_size: int) -> bytes:
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]
        i += lit
        if i >= n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        ml = token & 15
        if ml == 15:
            while True:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - off
        if off >= ml:
            out += out[start:start + ml]
        else:
            for k in range(ml):
                out.append(out[start + k])
    if len(out) != out_size:
        raise ValueError(f"lz4: got {len(out)} bytes, expected {out_size}")
    return bytes(out)


def load_image(path) -> bytes:
    d = open(path, "rb").read()
    if d[:4] != b"NSO0":
        raise ValueError(f"{path}: not an NSO")
    flags = struct.unpack_from("<I", d, 0xC)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    csizes = struct.unpack_from("<III", d, 0x60)
    bss = struct.unpack_from("<I", d, 0x3C)[0]
    img = bytearray(segs[2][1] + segs[2][2] + bss)
    for i, (off, loc, size) in enumerate(segs):
        raw = d[off:off + (csizes[i] if flags >> i & 1 else size)]
        img[loc:loc + size] = lz4_block_decompress(raw, size) if flags >> i & 1 else raw
    return bytes(img)


def symbols(img: bytes):
    """[(offset, size, name)] of the defined symbols, sorted by offset."""
    mod0 = struct.unpack_from("<I", img, 4)[0]
    if img[mod0:mod0 + 4] != b"MOD0":
        return []
    dyn = mod0 + struct.unpack_from("<i", img, mod0 + 4)[0]
    tags, i = {}, dyn
    while i + 16 <= len(img):
        tag, val = struct.unpack_from("<qQ", img, i)
        if tag == DT_NULL:
            break
        tags.setdefault(tag, val)
        i += 16
    strtab, symtab = tags.get(DT_STRTAB), tags.get(DT_SYMTAB)
    if strtab is None or symtab is None:
        return []
    out = []
    idx = 1
    while symtab + (idx + 1) * 24 <= strtab:
        st_name, _info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", img, symtab + idx * 24)
        if value and shndx:
            e = img.index(b"\0", strtab + st_name)
            out.append((value, size, img[strtab + st_name:e].decode(errors="replace")))
        idx += 1
    out.sort()
    return out


if __name__ == "__main__":
    syms = symbols(load_image(sys.argv[1]))
    for v, s, n in syms:
        if len(sys.argv) < 3 or sys.argv[2] in n:
            print(f"{v:#x} {s:#x} {n}")
