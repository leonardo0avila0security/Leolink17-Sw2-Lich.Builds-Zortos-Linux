#!/usr/bin/env python3
# Disassembles functions of a Switch NSO by module offset, with the import (PLT) or export name of
# every call target, to read a crash's code on the player's machine. Standalone: needs only capstone
# (shipped in orbitals-recomp's setup\python) and the player's own exefs.
#
#   python disasm_fn.py <exefs dir> main+0x1759b20 main+0x175dbd0 [--count 300] [--out fn.txt]
#
# A function is listed from its address to its first RET (or --count instructions). Nothing of the
# game is written anywhere but --out (default: the console).
import argparse
import struct
import sys
from pathlib import Path

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
except ImportError:
    sys.exit("capstone missing: run it with orbitals-recomp's setup\\python\\python.exe")


def lz4(src, size):
    out, i, n = bytearray(), 0, len(src)
    while i < n:
        t = src[i]
        i += 1
        lit = t >> 4
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
        off = src[i] | src[i + 1] << 8
        i += 2
        ml = t & 15
        if ml == 15:
            while True:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        s = len(out) - off
        if off >= ml:
            out += out[s:s + ml]
        else:
            for k in range(ml):
                out.append(out[s + k])
    return bytes(out)


def load(path):
    d = Path(path).read_bytes()
    flags = struct.unpack_from("<I", d, 0xC)[0]
    segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
    cs = struct.unpack_from("<III", d, 0x60)
    img = bytearray(segs[2][1] + segs[2][2] + struct.unpack_from("<I", d, 0x3C)[0])
    for i, (off, loc, size) in enumerate(segs):
        raw = d[off:off + (cs[i] if flags >> i & 1 else size)]
        img[loc:loc + size] = lz4(raw, size) if flags >> i & 1 else raw
    return bytes(img), segs[0][1] + segs[0][2]


def names(img):
    mod0 = struct.unpack_from("<I", img, 4)[0]
    dyn = mod0 + struct.unpack_from("<i", img, mod0 + 4)[0]
    tags, i = {}, dyn
    while True:
        tag, val = struct.unpack_from("<qQ", img, i)
        if tag == 0:
            break
        tags.setdefault(tag, val)
        i += 16
    strtab, symtab = tags[5], tags[6]

    def nm(idx):
        o = struct.unpack_from("<I", img, symtab + idx * 24)[0]
        return img[strtab + o:img.index(b"\0", strtab + o)].decode(errors="replace")

    exports, idx = {}, 1
    while symtab + (idx + 1) * 24 <= strtab:
        _, _, _, shndx, value, _ = struct.unpack_from("<IBBHQQ", img, symtab + idx * 24)
        if value and shndx:
            exports[value] = nm(idx)
        idx += 1
    got = {}
    for start, size in ((tags.get(23), tags.get(2)), (tags.get(7), tags.get(8))):
        if start:
            for j in range(start, start + size, 24):
                r_off, r_info, _ = struct.unpack_from("<QQq", img, j)
                if r_info >> 32:
                    got[r_off] = nm(r_info >> 32)
    return exports, got


def plt_import(img, addr, got):
    """Name of the import a PLT stub (ADRP x16; LDR x17, [x16, #o]; ...) jumps through."""
    if addr + 8 > len(img):
        return None
    a, b = struct.unpack_from("<II", img, addr)
    if (a & 0x9F00001F) != 0x90000010 or (b & 0xFFC003FF) != 0xF9400211:
        return None
    imm = ((a >> 29) & 3) | (((a >> 5) & 0x7FFFF) << 2)
    if imm & (1 << 20):
        imm -= 1 << 21
    page = (addr & ~0xFFF) + (imm << 12)
    return got.get(page + ((b >> 10) & 0xFFF) * 8)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exefs")
    ap.add_argument("where", nargs="+", help="module+0xoffset, e.g. main+0x1759b20")
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--out")
    a = ap.parse_args()
    out = open(a.out, "w") if a.out else sys.stdout
    mods = {}
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for w in a.where:
        mod, _, off = w.partition("+")
        start = int(off, 16)
        if mod not in mods:
            img, text_end = load(Path(a.exefs) / mod)
            mods[mod] = (img, text_end, *names(img))
        img, text_end, exports, got = mods[mod]
        print(f"\n== {mod}+{start:#x}" + (f" {exports[start]}" if start in exports else ""), file=out)
        n = 0
        for ins in md.disasm(img[start:min(start + a.count * 4, text_end)], start):
            note = ""
            if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#"):
                t = int(ins.op_str[1:], 16)
                imp = plt_import(img, t, got)
                note = f"   ; {imp}" if imp else (f"   ; {exports[t]}" if t in exports else "")
            print(f"{mod}+{ins.address:#x}: {ins.mnemonic:8} {ins.op_str}{note}", file=out)
            n += 1
            if ins.mnemonic in ("ret", "retaa", "retab") or n >= a.count:
                break


if __name__ == "__main__":
    main()
