#!/usr/bin/env python3
# Packs the output of run-analysis into two zips in <out dir>:
#   lichii-logs-summary.zip  small (a few MB): report, digest of the log, SVC/IPC list, top
#                            functions. This is the one to send first.
#   lichii-logs-full.zip     everything: raw log, block trace, analysis, debug dumps.
# Usage: make_bundle.py <out dir>
import collections
import json
import platform
import re
import sys
import zipfile
from pathlib import Path

PROBLEM = re.compile(r"error|warn|critical|fail|unimplemented|unknown|abort|crash|assert|fault|"
                     r"not supported|stub|invalid", re.I)
KEEP = re.compile(r"Lichii Version|Booting game|loaded module|Loader|Vulkan|GPU|driver", re.I)


def digest(log: Path, dest: Path):
    if not log.exists():
        dest.write_text("no log\n")
        return
    lines = log.read_text(errors="replace").splitlines()
    head = [l for l in lines[:2000] if KEEP.search(l)][:200]
    counts, first = collections.Counter(), {}
    for l in lines:
        if PROBLEM.search(l):
            key = re.sub(r"0x[0-9a-fA-F]+|\d+", "#", re.sub(r"^\[[^\]]*\]\s*\S*\s*", "", l))[:200]
            counts[key] += 1
            first.setdefault(key, l[:400])
    out = [f"log lines: {len(lines)}", f"host: {platform.platform()}", "", "## Start of log"] + head
    out += ["", "## Distinct warnings/errors (count, first occurrence)"]
    for key, n in counts.most_common(300):
        out.append(f"{n:>7}  {first[key]}")
    out += ["", "## Last 300 lines"] + [l[:400] for l in lines[-300:]]
    dest.write_text("\n".join(out) + "\n")


def main():
    out = Path(sys.argv[1])
    analysis = out / "analysis"
    digest(out / "eden_log.txt", out / "log_digest.txt")

    with zipfile.ZipFile(out / "lichii-logs-summary.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.write(out / "log_digest.txt", "log_digest.txt")
        for name in ("report.md", "modules.json", "indirect.json", "svc_ipc.json"):
            if (analysis / name).exists():
                z.write(analysis / name, name)
        fj = analysis / "functions.json"
        if fj.exists():
            funcs = sorted(json.loads(fj.read_text()), key=lambda f: -f["callers"])[:3000]
            z.writestr("functions_top.json", json.dumps(funcs, indent=1))

    with zipfile.ZipFile(out / "lichii-logs-full.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in out.rglob("*"):
            if p.is_file() and p.suffix not in (".zip", ".ini"):
                z.write(p, p.relative_to(out))

    for name in ("lichii-logs-summary.zip", "lichii-logs-full.zip"):
        print(f"{out / name}  {(out / name).stat().st_size / 1048576:.1f} MiB")


if __name__ == "__main__":
    main()
