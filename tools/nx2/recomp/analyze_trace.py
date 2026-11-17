#!/usr/bin/env python3
# Turns the output of an analysis run into the inputs a static recompiler needs.
#
#   analyze_trace.py --blocks blocks.jsonl --log eden_log.txt [--exefs <dir>] --out <dir>
#
# Inputs
#   --blocks  LICHII_BLOCK_TRACE file: one JSON line per JIT-compiled guest block.
#   --log     emulator log. Uses "loaded module <name> @ <addr>" (run with
#             --filter "*:Info Loader:Debug"), "svc 0x.. in" (EDEN_NX2_SVC_TRACE=1) and
#             "ipc <service>::<cmd> (<name>)" (EDEN_NX2_IPC_TRACE=1).
#   --exefs   optional ExeFS dir with the NSOs. Adds module sizes and exported symbol names
#             (reads your own files; nothing is copied into the output except symbol names).
#
# Outputs (in --out)
#   modules.json     module name, base, size, executed bytes and block count
#   blocks.json      per module: executed blocks as module-relative [start, end, kind, next]
#   functions.json   function entry candidates with callers and the blocks they reach
#   indirect.json    blocks that end in an indirect branch (jump tables, virtual calls, returns
#                    not covered by the return stack). Targets are unknown statically.
#   svc_ipc.json     SVC numbers and IPC service::command pairs the run used, with counts
#   report.md        summary
#
# Limits: coverage only contains what the run executed. Function entries are heuristic
# (see classify_entries); exported symbols are exact. Treat both as seeds, not ground truth.
import argparse
import bisect
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MODULE_RE = re.compile(r"loaded module (\S+) @ (0x[0-9a-fA-F]+)")
SIZE_RE = re.compile(r"Module (\S+) loaded at (0x[0-9a-fA-F]+) \(size (0x[0-9a-fA-F]+)\)")
SVC_RE = re.compile(r"svc (0x[0-9a-fA-F]+) in")
IPC_RE = re.compile(r"\bt?ipc (\S+?)::(\d+) \(([^)]*)\)")


def parse_log(path):
    modules, svcs, ipcs = {}, collections.Counter(), collections.Counter()
    sizes = {}
    with open(path, errors="replace") as f:
        for line in f:
            m = SIZE_RE.search(line)
            if m:
                sizes[m.group(1)] = int(m.group(3), 16)
                continue
            m = MODULE_RE.search(line)
            if m:
                modules[m.group(1)] = int(m.group(2), 16)
                continue
            m = SVC_RE.search(line)
            if m:
                svcs[m.group(1)] += 1
                continue
            m = IPC_RE.search(line)
            if m:
                ipcs[(m.group(1), int(m.group(2)), m.group(3))] += 1
    return modules, svcs, ipcs, sizes


def parse_blocks(path):
    blocks = {}
    with open(path) as f:
        for line in f:
            try:
                b = json.loads(line)
            except json.JSONDecodeError:
                continue  # truncated last line of a killed run
            pc, end = int(b["pc"], 16), int(b["end"], 16)
            blocks[(pc, end)] = (pc, end, b["term"], b["cond"], [int(x, 16) for x in b["next"]])
    return list(blocks.values())


def load_exefs(exefs):
    from nso_syms import load_image, parse  # noqa: E402
    info = {}
    for nso in sorted(Path(exefs).iterdir()):
        if nso.name in ("main.npdm",) or nso.suffix:
            continue
        try:
            img = load_image(str(nso))
        except Exception:
            continue
        syms = {}
        try:
            for value, _size, name in parse(img)[0]:
                syms[value] = name
        except Exception:
            pass
        info[nso.name] = (len(img), syms)
    return info


def classify_entries(blocks):
    """Entry candidates: targets of a non-fallthrough link edge, ranked by distinct callers."""
    callers = collections.defaultdict(set)
    for pc, end, term, cond, nxt in blocks:
        for t in nxt:
            if t != end:
                callers[t].add(pc)
    starts = {b[0] for b in blocks}
    return {t: c for t, c in callers.items() if t in starts}


def reach(entry, by_pc, entries):
    seen, stack = set(), [entry]
    while stack:
        pc = stack.pop()
        if pc in seen or pc not in by_pc:
            continue
        if pc != entry and pc in entries and len(entries[pc]) > 1:
            continue  # another function with several callers
        seen.add(pc)
        stack.extend(by_pc[pc][4])
    return sorted(seen)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--exefs")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    log_modules, svcs, ipcs, log_sizes = parse_log(a.log)
    blocks = parse_blocks(a.blocks)
    exefs = load_exefs(a.exefs) if a.exefs else {}
    if not log_modules:
        sys.exit("no 'loaded module' lines in the log: run with --filter '*:Info Loader:Debug'")

    order = sorted(log_modules.items(), key=lambda kv: kv[1])
    bases = [b for _, b in order]

    def module_of(addr):
        i = bisect.bisect_right(bases, addr) - 1
        if i < 0:
            return None
        name, base = order[i]
        size = exefs.get(name, (None, {}))[0] or log_sizes.get(name)
        if size is not None and addr >= base + size:
            return None
        return name, base

    per_module = collections.defaultdict(list)
    for b in blocks:
        m = module_of(b[0])
        if m:
            per_module[m[0]].append(b)

    entries = classify_entries(blocks)
    by_pc = {b[0]: b for b in blocks}

    modules_json, blocks_json = {}, {}
    for name, base in order:
        bl = per_module.get(name, [])
        modules_json[name] = {
            "base": hex(base),
            "size": (exefs[name][0] if name in exefs else log_sizes.get(name)),
            "blocks": len(bl),
            "executed_bytes": sum(e - p for p, e, *_ in bl),
        }
        blocks_json[name] = [[hex(p - base), hex(e - base), t, [hex(n - base) for n in nx]]
                             for p, e, t, c, nx in sorted(bl)]

    functions = []
    for t, callers in sorted(entries.items()):
        m = module_of(t)
        if not m:
            continue
        name, base = m
        sym = exefs.get(name, (0, {}))[1].get(t - base)
        body = reach(t, by_pc, entries)
        functions.append({
            "module": name, "entry": hex(t - base), "symbol": sym,
            "callers": len(callers), "blocks": len(body),
            "bytes": sum(by_pc[p][1] - p for p in body),
        })
    indirect = []
    for p, e, t, c, nx in blocks:
        m = module_of(p)
        if m and t == "indirect":
            indirect.append({"module": m[0], "block": hex(p - m[1]), "end": hex(e - m[1])})

    svc_ipc = {
        "svc": {k: v for k, v in sorted(svcs.items())},
        "ipc": [{"service": s, "command": c, "name": n, "count": v} for (s, c, n), v in sorted(ipcs.items())],
    }

    for fname, data in [("modules.json", modules_json), ("blocks.json", blocks_json),
                        ("functions.json", functions), ("indirect.json", indirect),
                        ("svc_ipc.json", svc_ipc)]:
        (out / fname).write_text(json.dumps(data, indent=1))

    total = sum(m["executed_bytes"] for m in modules_json.values())
    lines = ["# Recompilation analysis", "",
             f"Blocks: {len(blocks)}, executed code: {total / 1024:.1f} KiB", "",
             "| Module | Base | Blocks | Executed KiB | Image KiB |", "|---|---|---|---|---|"]
    for n, m in modules_json.items():
        size = f"{m['size'] / 1024:.0f}" if m["size"] else "?"
        lines.append(f"| {n} | {m['base']} | {m['blocks']} | {m['executed_bytes'] / 1024:.1f} | {size} |")
    lines += ["", f"Function entry candidates: {len(functions)} "
              f"({sum(1 for f in functions if f['symbol'])} with exported symbols)",
              f"Indirect-branch blocks to resolve: {len(indirect)}",
              f"Distinct SVCs: {len(svcs)}, distinct IPC commands: {len(ipcs)}"]
    (out / "report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
