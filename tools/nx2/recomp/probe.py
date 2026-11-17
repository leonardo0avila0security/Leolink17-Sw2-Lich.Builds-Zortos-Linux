#!/usr/bin/env python3
# Guest function probe for Lichii: what the real game code receives and returns, as reference
# values for orbitals-recomp (pmocer-latibro), which replaces those functions with its own.
#
# It drives Lichii's GDB stub (eden-cli -d <port>): software breakpoints on the probed functions,
# on each hit the registers, the memory the arguments point to and a frame-pointer backtrace;
# optionally a second breakpoint on the return address for the return value and the output
# buffers; optionally a write watchpoint on an object (who signals an event). Then it resumes.
# Each stop costs a few milliseconds of the game's time, so every probe has a hit limit.
#
#   probe.py --port 6543 --log <eden log> [--log ...] --exefs <dir> --spec <json> --out <jsonl>
#            [--seconds N]
#
# Module bases differ per run (ASLR): they are read from the log's "Module X loaded at" lines,
# which the probe waits for. Addresses in the output are module-relative ("main+0x1540434") and
# named with the nearest exported symbol, the same notation as orbitals-recomp.
#
# Spec (JSON list), one object per probe:
#   name       label in the output
#   at         "sym:<exact mangled name>" or "<module>+0x<offset>"
#   dump       {"x0": 64, ...}: bytes to read at the address in that register, on entry
#   ret        "lr" (break at the return address), "next" (at pc+4: the probe is on a BL), or absent
#   ret_dump   [["x0", 40], ...]: bytes to read at the entry value of that register, on return;
#              a length "x1*40" multiplies the entry value of x1 by 40 (capped at 4096)
#   watch      ["x0", 8]: on the first hit, a write watchpoint on that many bytes at the register's
#              address; each write logs the writer
#   watch_max  writes to log (default 50)
#   max        hits to log before the breakpoint is removed (default 100)
#   bt         backtrace depth (default 12)
#   callsite   true: the probe is on a BL/BLR; the call's target is decoded and logged
#
# --summary writes a short text report (bases, per probe: hits, callers, targets, return values,
# wait times, the first buffers as 64-bit words) small enough to attach to a chat.
import argparse
import json
import re
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nso_lite import load_image, symbols  # noqa: E402

REGS = [f"x{i}" for i in range(31)] + ["sp", "pc", "cpsr"]
MODULE_RE = re.compile(r"Module (\S+) loaded at (0x[0-9a-fA-F]+) \(size (0x[0-9a-fA-F]+)\)")
ADDR_MASK = (1 << 48) - 1  # drop PAC / tag bits of return addresses


class StubGone(Exception):
    pass


class Rsp:
    def __init__(self, port, wait_s=600):
        deadline = time.time() + wait_s
        while True:
            try:
                self.s = socket.create_connection(("127.0.0.1", port), timeout=3)
                self.s.settimeout(None)
                break
            except OSError:
                if time.time() > deadline:
                    raise SystemExit(f"no GDB stub on port {port}: start eden-cli with -d {port}")
                time.sleep(0.5)
        self.buf = b""

    def _recv(self):
        chunk = self.s.recv(65536)
        if not chunk:
            raise StubGone
        self.buf += chunk

    def read_packet(self):
        while True:
            while b"$" not in self.buf:
                self._recv()
            start = self.buf.index(b"$")
            while b"#" not in self.buf[start:] or len(self.buf) < self.buf.index(b"#", start) + 3:
                self._recv()
            end = self.buf.index(b"#", start)
            data = self.buf[start + 1:end]
            self.buf = self.buf[end + 3:]
            self.s.sendall(b"+")
            return data.decode(errors="replace")

    def send(self, c):
        pkt = c.encode()
        self.s.sendall(b"$" + pkt + b"#" + f"{sum(pkt) & 0xff:02x}".encode())

    def cmd(self, c):
        self.send(c)
        return self.read_packet()

    def regs(self):
        r = self.cmd("g")
        vals, off = {}, 0
        for name in REGS:
            n = 4 if name == "cpsr" else 8
            if off + n * 2 > len(r):
                break
            vals[name] = int.from_bytes(bytes.fromhex(r[off:off + n * 2]), "little")
            off += n * 2
        return vals

    def mem(self, addr, length):
        out = b""
        while length > 0:
            n = min(length, 0x800)
            r = self.cmd(f"m{addr:x},{n:x}")
            try:
                part = bytes.fromhex(r)
            except ValueError:
                break
            if not part:
                break
            out += part
            addr += n
            length -= n
        return out


class Modules:
    def __init__(self, bases, exefs):
        self.mods = sorted(bases.items(), key=lambda kv: kv[1][0])  # name -> (base, size)
        self.syms = {}
        for name, _ in self.mods:
            path = Path(exefs) / name if exefs else None
            if path and path.is_file():
                try:
                    self.syms[name] = symbols(load_image(path))
                except Exception as e:  # a module we cannot read just has no names
                    print(f"warning: {path}: {e}", file=sys.stderr)

    def base(self, name):
        for n, (b, _s) in self.mods:
            if n == name:
                return b
        raise KeyError(name)

    def resolve(self, at):
        if at.startswith("sym:"):
            want = at[4:]
            for n, (b, _s) in self.mods:
                for off, _size, sname in self.syms.get(n, []):
                    if sname == want:
                        return b + off
            raise KeyError(f"symbol {want} not found (is --exefs set?)")
        mod, _, off = at.partition("+")
        return self.base(mod) + int(off, 16)

    def name(self, addr):
        addr &= ADDR_MASK
        for n, (b, s) in self.mods:
            if b <= addr < b + s:
                off = addr - b
                label = f"{n}+{off:#x}"
                best = None
                for so, ss, sn in self.syms.get(n, []):
                    if so > off:
                        break
                    best = (so, ss, sn)
                if best and (best[1] == 0 or off < best[0] + max(best[1], 1) + 0x10000):
                    label += f" ({best[2]}+{off - best[0]:#x})"
                return label
        return f"{addr:#x}"


def read_bases(logs, timeout_s):
    deadline = time.time() + timeout_s
    while True:
        bases = {}
        for p in logs:
            try:
                for line in open(p, errors="replace"):
                    m = MODULE_RE.search(line)
                    if m:
                        bases[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))
            except OSError:
                pass
        if "main" in bases and "sdk" in bases:
            return bases
        if time.time() > deadline:
            raise SystemExit(f"no 'Module main/sdk loaded at' lines in {logs}")
        time.sleep(1)


def call_target(insn, pc, regs):
    """Target of a BL (immediate) or BLR/BLRAA/BLRAB/BLRAAZ/BLRABZ (register), else None."""
    if insn >> 26 == 0b100101:  # BL imm26
        imm = insn & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        return pc + imm * 4, None
    if (insn & 0xFFFFFC1F) == 0xD63F0000 or (insn & 0xFEFFF800) == 0xD63F0800:
        n = (insn >> 5) & 31
        return regs.get(f"x{n}", 0) & ADDR_MASK, f"x{n}"
    return None, None


def mem_len(spec, entry_regs):
    if isinstance(spec, int):
        return spec
    reg, _, mul = str(spec).partition("*")
    return min(entry_regs.get(reg, 0) * (int(mul) if mul else 1), 4096)


def write_summary(events_path, path, mods, probes):
    import collections
    import statistics
    evs = [json.loads(line) for line in open(events_path) if line.strip()]
    lines = ["# Lichii probe summary", ""]
    lines += [f"{n} @ {b:#x} size {s:#x}" for n, (b, s) in mods.mods]
    for p in probes.values():
        name = p["name"]
        calls = [e for e in evs if e["probe"] == name and e["ev"] == "call"]
        rets = [e for e in evs if e["probe"] == name and e["ev"] == "ret"]
        writes = [e for e in evs if e["probe"] == name and e["ev"] == "write"]
        lines += ["", f"## {name} at {mods.name(p['addr'])}: {len(calls)} calls, {len(rets)} returns,"
                  f" {len(writes)} writes"]
        callers = collections.Counter(e["bt"][0] for e in calls if e.get("bt"))
        for c, n in callers.most_common(5):
            lines.append(f"  caller {c}: {n}")
        targets = collections.Counter(e.get("target") for e in calls if e.get("target"))
        for t, n in targets.most_common(5):
            lines.append(f"  target {t}: {n}")
        threads = collections.Counter(e["thread"] for e in calls)
        lines.append(f"  threads: {dict(threads)}")
        if calls:
            lines.append(f"  first call args {calls[0]['args']}")
            lines.append("  first backtrace: " + " <- ".join(calls[0].get("bt", [])[:8]))
        if rets:
            lines.append(f"  return x0: {dict(collections.Counter(e['x0'] for e in rets).most_common(8))}")
            waits = [e["waited_ms"] for e in rets]
            lines.append(f"  time to return ms: min {min(waits)} median {statistics.median(waits)} max {max(waits)}")
            lines.append("  first 40 returns (t, x0, ms): " + ", ".join(
                f"{e['t']}:{e['x0']}:{e['waited_ms']}" for e in rets[:40]))
            for e in rets[:24]:
                for k, v in e.items():
                    if k.startswith("*") and v:
                        words = [struct.unpack_from("<Q", bytes.fromhex(v), i)[0]
                                 for i in range(0, len(v) // 2 - 7, 8)]
                        lines.append(f"  t={e['t']} {k}: " + " ".join(f"{w:x}" for w in words[:40]))
        for e in calls[:6]:
            for k, v in e.items():
                if k.startswith("*") and v:
                    lines.append(f"  call {e['n']} {k}: {v[:128]}")
        for e in writes[:20]:
            lines.append(f"  write t={e['t']} thread {e['thread']} pc {e['pc']} value {e['value']} "
                         "bt " + " <- ".join(e.get("bt", [])[:6]))
    Path(path).write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=6543)
    ap.add_argument("--log", action="append", required=True)
    ap.add_argument("--exefs")
    ap.add_argument("--spec", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seconds", type=float, default=0, help="stop probing after this long (0: until exit)")
    ap.add_argument("--summary", help="also write a short text report here")
    a = ap.parse_args()

    spec = json.load(open(a.spec))
    print("waiting for the game to load...", flush=True)
    bases = read_bases(a.log, 900)
    mods = Modules(bases, a.exefs)
    for n, (b, s) in mods.mods:
        print(f"  {n} @ {b:#x} size {s:#x} ({len(mods.syms.get(n, []))} symbols)")

    probes = {}  # address -> probe
    for p in spec:
        try:
            addr = mods.resolve(p["at"])
        except KeyError as e:
            print(f"skip {p['name']}: {e}")
            continue
        p.update(addr=addr, hits=0, writes=0, watched=None)
        probes[addr] = p
        print(f"probe {p['name']} at {mods.name(addr)}")
    if not probes:
        raise SystemExit("no probe resolved")

    out = open(a.out, "w")
    t0 = time.time()

    def emit(ev):
        ev["t"] = round(time.time() - t0, 4)
        out.write(json.dumps(ev) + "\n")
        out.flush()

    rsp = Rsp(a.port)
    for _ in range(240):  # the stub reports a bogus thread until the process exists
        reason = rsp.cmd("?")
        m = re.search(r"thread:([0-9a-f]+);", reason)
        if m and int(m.group(1), 16) < 0x10000:
            break
        time.sleep(0.5)

    breaks = {}  # address -> reference count (entry probes and pending returns share them)

    def add_break(addr):
        if breaks.get(addr, 0) == 0:
            rsp.cmd(f"Z0,{addr:x},4")
        breaks[addr] = breaks.get(addr, 0) + 1

    def drop_break(addr):
        if breaks.get(addr, 0) == 0:
            return
        breaks[addr] -= 1
        if breaks[addr] == 0:
            del breaks[addr]
            rsp.cmd(f"z0,{addr:x},4")

    def backtrace(regs, depth):
        chain, fp = [mods.name(regs.get("x30", 0))], regs.get("x29", 0)
        for _ in range(depth):
            d = rsp.mem(fp, 16)
            if len(d) < 16:
                break
            nfp, ret = struct.unpack("<QQ", d)
            chain.append(mods.name(ret))
            if nfp <= fp:
                break
            fp = nfp
        return chain

    for addr in probes:
        add_break(addr)
    pending = {}  # (thread, return address) -> [(probe, entry regs, entry time)]
    print(f"probing {len(probes)} functions; writing {a.out}", flush=True)

    try:
        while True:
            if a.seconds and time.time() - t0 > a.seconds:
                break
            if not any(p["hits"] < p.get("max", 100) for p in probes.values()) and not pending:
                break
            reason = rsp.cmd("c")
            if reason[:1] in ("W", "X"):
                break
            tid_m = re.search(r"thread:([0-9a-f]+);", reason)
            tid = tid_m.group(1) if tid_m else "?"
            if tid_m:
                rsp.cmd(f"Hg{tid}")
            watch_m = re.search(r"watch:([0-9a-f]+);", reason)
            regs = rsp.regs()
            pc = regs.get("pc", 0)

            if watch_m:
                waddr = int(watch_m.group(1), 16)
                for p in probes.values():
                    if p["watched"] == waddr:
                        p["writes"] += 1
                        emit({"ev": "write", "probe": p["name"], "thread": tid, "pc": mods.name(pc),
                              "value": rsp.mem(waddr, p["watch"][1]).hex(),
                              "bt": backtrace(regs, p.get("bt", 12))})
                        if p["writes"] >= p.get("watch_max", 50):
                            rsp.cmd(f"z2,{waddr:x},{p['watch'][1]:x}")
                            p["watched"] = -1
                continue

            handled = False
            for key in [(tid, pc)]:
                if key in pending and pending[key]:
                    p, entry, t_in = pending[key].pop()
                    if not pending[key]:
                        del pending[key]
                    ev = {"ev": "ret", "probe": p["name"], "thread": tid, "x0": f"{regs.get('x0', 0):#x}",
                          "x1": f"{regs.get('x1', 0):#x}", "waited_ms": round((time.time() - t_in) * 1000, 2)}
                    for reg, ln in p.get("ret_dump", []):
                        ev[f"*{reg}"] = rsp.mem(entry.get(reg, 0), mem_len(ln, entry)).hex()
                    emit(ev)
                    drop_break(pc)
                    handled = True

            p = probes.get(pc)
            if p and p["hits"] < p.get("max", 100):
                p["hits"] += 1
                handled = True
                ev = {"ev": "call", "probe": p["name"], "n": p["hits"], "thread": tid,
                      "args": {r: f"{regs.get(r, 0):#x}" for r in ("x0", "x1", "x2", "x3", "x4")},
                      "bt": backtrace(regs, p.get("bt", 12))}
                for reg, ln in p.get("dump", {}).items():
                    ev[f"*{reg}"] = rsp.mem(regs.get(reg, 0), ln).hex()
                if p.get("callsite"):
                    raw = rsp.mem(pc, 4)
                    if len(raw) == 4:
                        target, via = call_target(struct.unpack("<I", raw)[0], pc, regs)
                        ev["insn"] = raw[::-1].hex()
                        if target is not None:
                            ev["target"] = mods.name(target)
                            if via:
                                ev["via"] = via
                emit(ev)
                if p.get("ret"):
                    ret = (pc + 4) if p["ret"] == "next" else (regs.get("x30", 0) & ADDR_MASK)
                    pending.setdefault((tid, ret), []).append((p, regs, time.time()))
                    add_break(ret)
                if p.get("watch") and p["watched"] is None:
                    reg, ln = p["watch"]
                    waddr = regs.get(reg, 0)
                    r = rsp.cmd(f"Z2,{waddr:x},{ln:x}")
                    p["watched"] = waddr if r == "OK" else -1
                    emit({"ev": "watch", "probe": p["name"], "addr": f"{waddr:#x}", "reply": r})
                if p["hits"] >= p.get("max", 100):
                    drop_break(pc)
                    print(f"{p['name']}: {p['hits']} hits, done", flush=True)

            if not handled and pc not in breaks:
                continue  # a stop we did not cause (another debugger event): just resume
            # Step the stopped thread over the breakpoint, then put it back if still wanted.
            if pc in breaks:
                rsp.cmd(f"z0,{pc:x},4")
                rsp.cmd("s")
                rsp.cmd(f"Z0,{pc:x},4")
    except (StubGone, ConnectionError):
        print("the emulator closed the connection")
    finally:
        try:
            for addr in list(breaks):
                rsp.cmd(f"z0,{addr:x},4")
            for p in probes.values():
                if p["watched"] not in (None, -1):
                    rsp.cmd(f"z2,{p['watched']:x},{p['watch'][1]:x}")
            rsp.send("D")
        except Exception:
            pass
        out.close()
        for p in probes.values():
            print(f"{p['name']}: {p['hits']} calls, {p['writes']} writes")
        if a.summary:
            write_summary(a.out, a.summary, mods, probes)
            print(f"summary: {a.summary}")
        print(f"done: {a.out}")


if __name__ == "__main__":
    main()
