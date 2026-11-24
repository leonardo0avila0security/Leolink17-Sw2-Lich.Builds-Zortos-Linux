#!/usr/bin/env python3
"""
Orbitals Crash C — extracteur runtime corrigé.

Corrections par rapport au premier extracteur :
- MINIDUMP_EXCEPTION_STREAM.ThreadContext est à +0xA0 (taille) / +0xA4 (RVA).
- Les piles sont relues par adresse virtuelle depuis Memory64List/MemoryList,
  au lieu de dépendre uniquement du RVA du descripteur de pile.
- Les contextes CPU et les piles sont vérifiés avant export.
- Les zones de code autour des dispatchers, de l'appelant et du wrapper sont
  extraites pour permettre le désassemblage.

Usage :
  py .\\extraire_orbitals_memcpy_runtime_corrige.py "C:\\OrbitalsDumps\\orbitals-recomp.exe.16952.dmp"

Sortie :
  orbitals_memcpy_runtime_corrige.zip à côté du dump.
"""

import argparse
import mmap
import struct
import sys
import zipfile
from pathlib import Path

MDMP_SIGNATURE = 0x504D444D
THREAD_LIST = 3
MODULE_LIST = 4
MEMORY_LIST = 5
EXCEPTION_STREAM = 6
MEMORY64_LIST = 9

RETURN_RVAS = {
    0x1B5A9337: "retour_apres_premier_memcpy",
    0x1B5A939F: "retour_apres_second_memcpy",
    0x1C11DF58: "retour_interne_wrapper",
}

def read_at(f, offset, size):
    if offset < 0 or size < 0:
        raise ValueError("Offset/taille négatif.")
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError(f"Lecture incomplète à l'offset fichier 0x{offset:X}.")
    return data

def u32(f, offset):
    return struct.unpack("<I", read_at(f, offset, 4))[0]

def u64(f, offset):
    return struct.unpack("<Q", read_at(f, offset, 8))[0]

def parse_streams(f, file_size):
    if file_size < 32 or u32(f, 0) != MDMP_SIGNATURE:
        raise ValueError("Signature MDMP absente ou fichier trop court.")
    count = u32(f, 8)
    directory = u32(f, 12)
    if count > 100000 or directory + count * 12 > file_size:
        raise ValueError("Répertoire des streams invalide.")
    result = []
    for i in range(count):
        typ, size, rva = struct.unpack("<III", read_at(f, directory + i * 12, 12))
        if rva <= file_size and size <= file_size - rva:
            result.append((typ, size, rva))
    return result

def stream_of(streams, typ):
    return next((s for s in streams if s[0] == typ), None)

def read_dump_string(f, rva, file_size):
    if not rva or rva + 4 > file_size:
        return "<nom indisponible>"
    length = u32(f, rva)
    if length > 32768 or (length & 1) or rva + 4 + length > file_size:
        return "<nom invalide>"
    return read_at(f, rva + 4, length).decode("utf-16le", errors="replace").rstrip("\0")

def parse_modules(f, streams, file_size):
    entry = stream_of(streams, MODULE_LIST)
    modules = []
    if not entry:
        return modules
    _, size, rva = entry
    if size < 4:
        return modules
    count = u32(f, rva)
    if count > 100000 or 4 + count * 108 > size:
        raise ValueError("ModuleList invalide.")
    for i in range(count):
        m = rva + 4 + i * 108
        modules.append((u64(f, m), u32(f, m + 8),
                        read_dump_string(f, u32(f, m + 20), file_size)))
    return modules

def parse_memory_ranges(f, streams, file_size):
    ranges = []
    entry = stream_of(streams, MEMORY64_LIST)
    if entry:
        _, size, rva = entry
        if size >= 16:
            count = u64(f, rva)
            file_pos = u64(f, rva + 8)
            if count > 2_000_000 or 16 + count * 16 > size:
                raise ValueError("Memory64List invalide.")
            for i in range(count):
                va, length = struct.unpack("<QQ", read_at(f, rva + 16 + i * 16, 16))
                if length and file_pos <= file_size and length <= file_size - file_pos:
                    ranges.append((va, length, file_pos))
                file_pos += length

    entry = stream_of(streams, MEMORY_LIST)
    if entry:
        _, size, rva = entry
        if size >= 4:
            count = u32(f, rva)
            if count <= 2_000_000 and 4 + count * 16 <= size:
                for i in range(count):
                    va, length, data_rva = struct.unpack("<QII", read_at(f, rva + 4 + i * 16, 16))
                    if length and data_rva <= file_size and length <= file_size - data_rva:
                        ranges.append((va, length, data_rva))
    return sorted(ranges, key=lambda x: (x[0], -x[1]))

def read_virtual(f, ranges, address, length):
    """Lit une plage virtuelle, même si elle traverse plusieurs descripteurs."""
    if address < 0 or length < 0:
        return None
    if length == 0:
        return b""
    out = bytearray()
    pos = address
    remaining = length
    while remaining:
        candidates = [r for r in ranges if r[0] <= pos < r[0] + r[1]]
        if not candidates:
            return None
        # Préfère le descripteur qui couvre le plus loin l'adresse courante.
        start, size, file_pos = max(candidates, key=lambda r: r[0] + r[1])
        take = min(remaining, start + size - pos)
        out.extend(read_at(f, file_pos + pos - start, take))
        pos += take
        remaining -= take
    return bytes(out)

def module_for(modules, address):
    for base, size, name in modules:
        if base <= address < base + size:
            return f"{name}+0x{address-base:X}"
    return "<aucun module déclaré>"

def parse_amd64_context(data):
    # Offsets définis par CONTEXT AMD64 Windows.
    if len(data) < 256:
        return None
    names_offsets = [
        ("RAX",120),("RCX",128),("RDX",136),("RBX",144),
        ("RSP",152),("RBP",160),("RSI",168),("RDI",176),
        ("R8",184),("R9",192),("R10",200),("R11",208),
        ("R12",216),("R13",224),("R14",232),("R15",240),
        ("RIP",248),
    ]
    regs = {name: struct.unpack_from("<Q", data, off)[0]
            for name, off in names_offsets}
    regs["ContextFlags"] = struct.unpack_from("<I", data, 48)[0]
    return regs

def add_file(files, name, data):
    if data is not None:
        files[name] = data

def main():
    ap = argparse.ArgumentParser(description="Extraction runtime corrigée pour Orbitals Crash C.")
    ap.add_argument("dump", help="Chemin du minidump .dmp")
    ap.add_argument("-o", "--output", help="Chemin du ZIP de sortie")
    args = ap.parse_args()

    dump = Path(args.dump).expanduser()
    if not dump.is_file():
        print(f"Dump introuvable : {dump}", file=sys.stderr)
        return 2
    output = Path(args.output) if args.output else dump.with_name("orbitals_memcpy_runtime_corrige.zip")
    files = {}
    report = [
        "ORBITALS CRASH C — EXTRACTION RUNTIME CORRIGÉE",
        f"Dump : {dump}",
        f"Taille : {dump.stat().st_size:,} octets",
        "Lecture seule : le dump original n'est pas modifié.",
        "",
    ]

    with dump.open("rb") as f:
        file_size = dump.stat().st_size
        streams = parse_streams(f, file_size)
        ranges = parse_memory_ranges(f, streams, file_size)
        modules = parse_modules(f, streams, file_size)
        report.append(f"Streams valides : {len(streams)} | plages mémoire : {len(ranges):,}")
        report.append(f"Mémoire décrite : {sum(x[1] for x in ranges):,} octets")

        dll = next((m for m in modules if m[2].lower().replace("/", "\\").endswith("orbitalgame.dll")), None)
        exe = next((m for m in modules if m[2].lower().replace("/", "\\").endswith("orbitals-recomp.exe")), None)
        if not dll:
            raise ValueError("orbitalgame.dll absent du ModuleList.")
        if not exe:
            raise ValueError("orbitals-recomp.exe absent du ModuleList.")
        dll_base, dll_size, dll_name = dll
        exe_base, exe_size, exe_name = exe
        report += [
            f"orbitalgame.dll : base=0x{dll_base:016X} taille=0x{dll_size:X}",
            f"orbitals-recomp.exe : base=0x{exe_base:016X} taille=0x{exe_size:X}",
            "",
            "[DISPATCHERS — SLOTS ET CIBLES RUNTIME]",
        ]

        slot_specs = [
            ("resolver_flag", dll_base + 0x1D6E4040, 4),
            ("slot_dispatch_1", dll_base + 0x1D0744C8, 8),
            ("slot_dispatch_2", dll_base + 0x1D0744D8, 8),
        ]
        targets = {}
        for name, va, width in slot_specs:
            raw = read_virtual(f, ranges, va, width)
            if raw is None:
                report.append(f"{name} @ 0x{va:016X} : NON CAPTURÉ")
                continue
            value = int.from_bytes(raw, "little")
            report.append(f"{name} @ 0x{va:016X} = 0x{value:X}")
            if name.startswith("slot_"):
                targets[name] = value
                report.append(f"  cible : {module_for(modules, value)}")

        guest_got = read_virtual(f, ranges, 0x700900A008, 8)
        report.append("GOT guest @ 0x700900A008 : " +
                      ("NON CAPTURÉ" if guest_got is None else f"0x{int.from_bytes(guest_got, 'little'):016X}"))
        report.append("")

        # Code complet autour des deux cibles de dispatch et des sites d'appel connus.
        code_specs = []
        for name, va in targets.items():
            code_specs.append((f"{name}_code", va, 0x300))
        code_specs += [
            ("caller_main_1B5A8F00", dll_base + 0x1B5A8F00, 0x1000),
            ("caller_main_1B5A9300", dll_base + 0x1B5A9300, 0x240),
            ("wrapper_1C11DEE0", dll_base + 0x1C11DEE0, 0x240),
            ("wrapper_internal_1C11DF00", dll_base + 0x1C11DF00, 0x240),
            ("runtime_resolver_1C7ED0C0", dll_base + 0x1C7ED0C0, 0x500),
            ("runtime_call_dispatch_1C7ED0E0", dll_base + 0x1C7ED0E0, 0x700),
            ("dll_memcpy_1C7C6F90", dll_base + 0x1C7C6F90, 0x300),
            ("dll_memmove_1C7C6CD0", dll_base + 0x1C7C6CD0, 0x300),
            ("exe_copy_helper_40C000", exe_base + 0x40C00, 0x180),
            ("exe_memcpy_thunk_70C400", exe_base + 0x70C400, 0x180),
            ("exe_pre_copy_helper_29FCB0", exe_base + 0x29FCB0, 0x180),
        ]
        # Données référencées par les dispatchers observés dans le premier ZIP.
        global_specs = [
            ("dispatch1_flag_global", exe_base + 0x909E40, 0x40),
            ("dispatch1_state_global", exe_base + 0x7183B8, 0x40),
            ("dispatch2_globals", exe_base + 0x1AA0A080, 0x100),
        ]
        for name, va, length in code_specs + global_specs:
            data = read_virtual(f, ranges, va, length)
            if data is None:
                report.append(f"{name} @ 0x{va:016X} : non capturé")
            else:
                add_file(files, name + ".bin", data)
                report.append(f"{name} @ 0x{va:016X} : {len(data)} octets extraits")
        report.append("")

        # ExceptionStream : ThreadContext est le LocationDescriptor à +0xA0.
        exception_tid = None
        exception_regs = None
        ex = stream_of(streams, EXCEPTION_STREAM)
        if ex:
            _, ex_size, ex_rva = ex
            if ex_size >= 168:
                exception_tid = u32(f, ex_rva)
                ex_code = u32(f, ex_rva + 8)
                ex_flags = u32(f, ex_rva + 12)
                ex_address = u64(f, ex_rva + 24)
                param_count = min(u32(f, ex_rva + 32), 15)
                report.append("[EXCEPTION WINDOWS]")
                report.append(f"Thread fautif : 0x{exception_tid:X}")
                report.append(f"Code : 0x{ex_code:08X} | flags=0x{ex_flags:X}")
                report.append(f"Adresse : 0x{ex_address:016X} ({module_for(modules, ex_address)})")
                for i in range(param_count):
                    report.append(f"ExceptionInformation[{i}] = 0x{u64(f, ex_rva + 40 + i*8):X}")
                # CORRECT: descriptor size at +160, RVA at +164.
                ctx_size = u32(f, ex_rva + 160)
                ctx_rva = u32(f, ex_rva + 164)
                report.append(f"ThreadContext descriptor : taille=0x{ctx_size:X} RVA=0x{ctx_rva:X}")
                if ctx_size and ctx_rva and ctx_rva <= file_size and ctx_size <= file_size - ctx_rva:
                    ctx_data = read_at(f, ctx_rva, min(ctx_size, 1_048_576))
                    add_file(files, "exception_context_amd64.bin", ctx_data)
                    exception_regs = parse_amd64_context(ctx_data)
                    if exception_regs:
                        report.append(f"CONTEXT flags=0x{exception_regs['ContextFlags']:08X}")
                        for reg in ["RIP","RSP","RBP","RAX","RBX","RCX","RDX","RSI","RDI","R8","R9","R10","R11","R12","R13","R14","R15"]:
                            report.append(f"  {reg}=0x{exception_regs[reg]:016X}")
                    else:
                        report.append("Contexte trop court pour décoder les registres AMD64.")
                else:
                    report.append("Contexte CPU absent ou descripteur invalide.")
                report.append("")
            else:
                report.append("ExceptionStream trop court.")
        else:
            report.append("ExceptionStream absent.")
            report.append("")

        # Inspecter les vrais arguments du memcpy et le bloc de contexte pointé par RSI.
        if exception_regs:
            rsi_ptr = exception_regs.get("RSI", 0)
            dst_ptr = exception_regs.get("RCX", 0)
            src_ptr = exception_regs.get("RDX", 0)
            size_arg = exception_regs.get("R8", 0)
            report.append("[MEMOIRE AUTOUR DU MEMCPY FAUTIF]")
            report.append(f"RSI(context/descriptor)=0x{rsi_ptr:016X}")
            report.append(f"RCX(destination)=0x{dst_ptr:016X} RDX(source)=0x{src_ptr:016X} R8(size)=0x{size_arg:X}")
            if rsi_ptr:
                desc = read_virtual(f, ranges, rsi_ptr, 0x400)
                if desc:
                    add_file(files, "exception_rsi_descriptor_0x400.bin", desc)
                    rows = ["QWORDS DU BLOC RSI (0x400 octets)"]
                    for off in range(0, len(desc)-7, 8):
                        val = struct.unpack_from("<Q", desc, off)[0]
                        rows.append(f"+0x{off:03X} = 0x{val:016X}")
                    files["exception_rsi_descriptor_qwords.txt"] = ("\n".join(rows)+"\n").encode("utf-8")
                    report.append("Bloc RSI : 0x400 octets capturés.")
                else:
                    report.append("Bloc RSI : non capturé.")
            if dst_ptr:
                dest_mem = read_virtual(f, ranges, max(0, dst_ptr-0x80), 0x280)
                if dest_mem:
                    add_file(files, "memcpy_destination_neighborhood.bin", dest_mem)
                    report.append("Voisinage destination : 0x280 octets capturés.")
                else:
                    report.append("Voisinage destination : non capturé.")
            # Recherche le qword source exact dans les plages mémoire du dump.
            if src_ptr and src_ptr < 0x0000800000000000:
                needle = struct.pack("<Q", src_ptr)
                source_hits = []
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for va, length, file_pos in ranges:
                        pos = mm.find(needle, file_pos, file_pos + length)
                        while pos >= 0:
                            source_hits.append(va + (pos-file_pos))
                            if len(source_hits) >= 100:
                                break
                            pos = mm.find(needle, pos+1, file_pos+length)
                        if len(source_hits) >= 100:
                            break
                report.append(f"Occurrences du qword source dans les plages mémoire : {len(source_hits)}")
                for n, hit_va in enumerate(source_hits, 1):
                    report.append(f"  source_hit_{n}: 0x{hit_va:016X}")
                    around = read_virtual(f, ranges, max(0, hit_va-0x40), 0xA0)
                    if around:
                        add_file(files, f"source_pattern_hit_{n:02d}.bin", around)
            report.append("")

        # ThreadList : récupérer les piles par leur VA depuis Memory64List.
        thread_entry = stream_of(streams, THREAD_LIST)
        threads = []
        if thread_entry:
            _, t_size, t_rva = thread_entry
            if t_size >= 4:
                count = u32(f, t_rva)
                if count > 100000 or 4 + count * 48 > t_size:
                    raise ValueError("ThreadList invalide.")
                for i in range(count):
                    t = t_rva + 4 + i * 48
                    tid = u32(f, t)
                    stack_start = u64(f, t + 24)
                    stack_size = u32(f, t + 32)
                    stack_rva = u32(f, t + 36)
                    context_size = u32(f, t + 40)
                    context_rva = u32(f, t + 44)
                    threads.append((tid, stack_start, stack_size, stack_rva, context_size, context_rva))
        report.append(f"[THREADS] {len(threads)} threads")

        hits = []
        fault_stack = None
        for tid, stack_start, stack_size, stack_rva, context_size, context_rva in threads:
            if context_size and context_rva and context_rva <= file_size and context_size <= file_size - context_rva:
                if tid == exception_tid:
                    tctx = read_at(f, context_rva, min(context_size, 1_048_576))
                    add_file(files, f"thread_{tid:08X}_context.bin", tctx)
                    tregs = parse_amd64_context(tctx)
                    if tregs:
                        report.append(f"Contexte ThreadList fautif : RIP=0x{tregs['RIP']:016X} RSP=0x{tregs['RSP']:016X}")
            if not stack_start or not stack_size or stack_size > 128 * 1024 * 1024:
                continue
            stack = read_virtual(f, ranges, stack_start, stack_size)
            if stack is None and stack_rva and stack_rva <= file_size and stack_size <= file_size - stack_rva:
                stack = read_at(f, stack_rva, stack_size)
            if stack is None:
                continue
            if tid == exception_tid:
                fault_stack = (stack_start, stack)
                add_file(files, f"thread_{tid:08X}_stack.bin", stack)
            align = (-stack_start) & 7
            for off in range(align, len(stack) - 7, 8):
                value = struct.unpack_from("<Q", stack, off)[0]
                if value in (dll_base + rva for rva in RETURN_RVAS):
                    rva = value - dll_base
                    hits.append((tid, stack_start, stack, off, value, RETURN_RVAS[rva]))

        report.append("")
        report.append("[RETOURS TROUVÉS DANS LES PILES]")
        report.append(f"Occurrences : {len(hits)}")
        if not hits:
            report.append("Aucun des retours recherchés n'a été trouvé dans les piles récupérées.")
        for index, (tid, stack_start, stack, off, ret_va, label) in enumerate(hits[:100], 1):
            stack_va = stack_start + off
            report.append("")
            report.append(f"{index}. Thread=0x{tid:X} | {label}")
            report.append(f"   retour=0x{ret_va:016X} ({module_for(modules, ret_va)})")
            report.append(f"   emplacement pile=0x{stack_va:016X} | offset=0x{off:X}")
            lo, hi = max(0, off - 0x80), min(len(stack), off + 0x100)
            add_file(files, f"stack_hit_{tid:08X}_{index:02d}.bin", stack[lo:hi])

            # Pour les retours après les appels au wrapper, le qword juste avant
            # l'adresse de retour est le candidat RSI sauvegardé par le prologue.
            if ret_va in (dll_base + 0x1B5A9337, dll_base + 0x1B5A939F) and off >= 8:
                saved_rsi = struct.unpack_from("<Q", stack, off - 8)[0]
                report.append(f"   qword pile-8 (candidat RSI sauvegardé)=0x{saved_rsi:016X}")
                ctx = read_virtual(f, ranges, saved_rsi, 0x200)
                if ctx is None:
                    report.append("   bloc pointé par RSI : non capturé à cette adresse.")
                else:
                    add_file(files, f"candidate_context_{tid:08X}_{index:02d}.bin", ctx)
                    report.append("   bloc pointé par RSI : 0x200 octets extraits.")
                    for field_off in range(0, 0x80, 8):
                        val = struct.unpack_from("<Q", ctx, field_off)[0]
                        report.append(f"     ctx+0x{field_off:02X} = 0x{val:016X}")

        if exception_regs:
            rsp = exception_regs["RSP"]
            report.append("")
            report.append("[VALIDATION RSP]")
            if fault_stack:
                ss, sb = fault_stack
                report.append(f"Pile du thread fautif : [0x{ss:016X}, 0x{ss+len(sb):016X})")
                report.append(f"RSP=0x{rsp:016X} dans la pile : {ss <= rsp < ss+len(sb)}")
            else:
                report.append("Pile du thread fautif non récupérée.")
            rip = exception_regs["RIP"]
            code = read_virtual(f, ranges, rip - 0x40, 0x100) if rip >= 0x40 else None
            if code:
                add_file(files, "exception_rip_neighborhood.bin", code)
                report.append("0x100 octets autour du RIP extraits.")
            else:
                report.append("Code autour du RIP non capturé.")

        report += [
            "",
            "[LIMITES]",
            "- Une adresse de retour trouvée dans une pile doit être confirmée par unwind x64/symboles.",
            "- Le qword pile-8 est présenté comme candidat RSI, pas comme preuve sans validation du prologue.",
            "- Les adresses guest 0x700... ne sont pas des adresses virtuelles Windows.",
            "- Aucune cause racine n'est déclarée sans relier le contexte d'appel aux instructions exactes.",
        ]

    files["rapport_runtime_memcpy_corrige.txt"] = "\n".join(report).encode("utf-8")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name, data in files.items():
            z.writestr(name, data)

    print(f"Terminé : {output}")
    print(f"Éléments extraits : {len(files)}")
    print(f"Taille ZIP : {output.stat().st_size:,} octets")
    print("Envoie uniquement ce ZIP ici.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())