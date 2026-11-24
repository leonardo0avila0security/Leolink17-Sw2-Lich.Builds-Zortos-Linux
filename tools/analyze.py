#!/usr/bin/env python3
"""
analyze.py : extraction de plages memoire depuis un minidump Windows.

Utile pour orbitals-recomp : le guest (main.nso) est mappe dans le processus
hote, donc TOUT le code guest est dispo dans le dump. On extrait les fenetres
de code autour des frames du backtrace d'abort, en texte, pour analyse.

Usage:
  python3 tools/analyze.py --dmp crash.dmp --sp <hex sp> \
      --frames <hex offsets sep espaces> --spans <start:end start:end ...> \
      --out analysis/

Genere :
  analysis/main-base.txt      base detecree du module guest (methode ancre pile)
  analysis/stack-qwords.txt   qwords de la pile autour de sp
  analysis/spans.txt          dwords des fenetres de code demandees
"""
import argparse, os, struct, sys

MINIDUMP_MAGIC = 0x4D444D4D  # 'MDMP'

def parse_streams(data):
    sig, ver, nstreams, dirrva, chk, tds, flags = struct.unpack_from('<IIIIIIQ', data, 0)
    if sig != MINIDUMP_MAGIC:
        raise SystemExit('pas un minidump (magic=%08x)' % sig)
    streams = {}
    off = dirrva
    for _ in range(nstreams):
        st, sz, rva = struct.unpack_from('<III', data, off)
        off += 12
        streams.setdefault(st, []).append((sz, rva))
    return streams

def memory_ranges(data, streams):
    """retourne [(start_va, size, file_rva)] tries par start_va"""
    ranges = []
    if 9 in streams:  # Memory64ListStream
        sz, rva = streams[9][0]
        n, base = struct.unpack_from('<QQ', data, rva)
        off = rva + 16
        cur = base
        for _ in range(n):
            start, length = struct.unpack_from('<QQ', data, off)
            off += 16
            ranges.append((start, length, cur))
            cur += length
    if 5 in streams:  # MemoryListStream (petites plages)
        sz, rva = streams[5][0]
        n, = struct.unpack_from('<I', data, rva)
        off = rva + 4
        for _ in range(n):
            start, dsz, rva2 = struct.unpack_from('<QII', data, off)
            off += 16
            ranges.append((start, dsz, rva2))
    ranges.sort(key=lambda r: r[0])
    return ranges

def find_main_base(data, ranges, sp, frame_offsets):
    """ancre : des qwords de la pile = base_guest + offset_de_frame connus"""
    for rs, rl, ro in ranges:
        if rs <= sp < rs + rl and rl >= 0x400:
            votes = {}
            base_seek = sp & ~0xF
            window_start = max(rs, base_seek - 0x800)
            window_end = min(rs + rl, base_seek + 0x1800)
            for a in range(window_start, window_end, 8):
                (v,) = struct.unpack_from('<Q', data, ro + (a - rs))
                for f in frame_offsets:
                    b = v - f
                    if 0x400000 <= b <= 0x800000000:
                        votes[b] = votes.get(b, 0) + 1
            if votes:
                best, n = max(votes.items(), key=lambda kv: kv[1])
                if n >= 3:
                    return best, n
            return None, 0
    return None, 0

def extract(data, ranges, start, end):
    out = bytearray()
    cur = start
    for rs, rl, ro in ranges:
        if rl == 0 or rs + rl <= cur:
            continue
        if rs >= end:
            break
        if rs > cur:
            out += b'\xcc' * (rs - cur)
            cur = rs
        take_end = min(end, rs + rl)
        out += data[ro + (cur - rs): ro + (take_end - rs)]
        cur = take_end
        if cur >= end:
            break
    if len(out) < end - start:
        out += b'\xcc' * (end - start - len(out))
    return bytes(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dmp', required=True)
    ap.add_argument('--sp', default='1183f9e00', help='guest sp a l abort, hex sans 0x')
    ap.add_argument('--frames', default='10a0 1f9878 181cc8 b9214 175a16c 1750b88 1750650 1718cf8 1d77d64 16198b4', help='offsets de frame connus, hex sep espaces')
    ap.add_argument('--spans', default='181b00:181d10 175a100:175a250 1750b00:1750c00 1750600:17506e0 1718c80:1718d40 1d77d00:1d77dc0 1619880:16198e0 bf030:bf070 1c690:1c6d0 b9180:b91f0', help='fenetres start:end, hex, sep espaces')
    ap.add_argument('--out', default='analysis')
    args = ap.parse_args()

    with open(args.dmp, 'rb') as fh:
        data = fh.read()
    streams = parse_streams(data)
    ranges = memory_ranges(data, streams)
    os.makedirs(args.out, exist_ok=True)

    frame_offsets = [int(x, 16) for x in args.frames.split()] if args.frames else []

    lines = []
    main_base = None
    if args.sp:
        sp = int(args.sp, 16)
        main_base, votes = find_main_base(data, ranges, sp, frame_offsets)
        lines.append('anchor sp=%s votes=%d main_base_dec=%s' %
                     (args.sp, votes, 'unknown' if main_base is None else str(main_base)))
        # pile brute autour de sp (0x400 octets avant, 0xC00 apres)
        for rs, rl, ro in ranges:
            if rs <= sp < rs + rl:
                lo = max(rs, sp - 0x400)
                hi = min(rs + rl, sp + 0xC00)
                blob = data[ro + (lo - rs): ro + (hi - rs)]
                with open(os.path.join(args.out, 'stack-qwords.txt'), 'w') as f:
                    for off in range(0, len(blob) - 7, 8):
                        (v,) = struct.unpack_from('<Q', blob, off)
                        f.write('%016x %016x\n' % (lo + off, v))
                break

    with open(os.path.join(args.out, 'main-base.txt'), 'w') as f:
        f.write('\n'.join(lines) + '\n')

    out_lines = ['k main_base=' + ('unknown' if main_base is None else '%d' % main_base)]
    for span in args.spans.split():
        s, e = span.split(':')
        start = int(s, 16) + (main_base or 0)
        end = int(e, 16) + (main_base or 0)
        blob = extract(data, ranges, start, end)
        out_lines.append('k span %s rel base=%d' % (span, start))
        # imprime par lignes de 4 dwords : valeur hex du dword LE (valeur reelle A64)
        for i in range(0, len(blob) - 3, 4):
            (w,) = struct.unpack_from('<I', blob, i)
            if i % 16 == 0:
                out_lines.append('%08x:' % (start + i))
            out_lines.append(' %08x' % w)
    with open(os.path.join(args.out, 'spans.txt'), 'w') as f:
        f.write('\n'.join(out_lines) + '\n')
    print('OK spans=%d main_base=%s' % (len(args.spans.split()), main_base))

if __name__ == '__main__':
    main()
