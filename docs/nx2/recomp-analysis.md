# Analysis build for recompilation work

Goal: watch how a title (here Orbitals, `040032B023CA4000`) runs in Lichii and turn that into
inputs for a static recompilation: which guest code runs, where it branches, which SVCs and
services it calls, and what memory and files it uses. Use only your own legally obtained copy.

## What it adds

| Piece | Where | Output |
|---|---|---|
| Guest block tracer | `LICHII_BLOCK_TRACE=<file>`, `src/dynarmic/.../backend/x64/block_trace.cpp` | One JSON line per compiled A64 block: `pc`, `end`, terminal kind (`link`, `indirect`, `ret`), static successors. Off by default. |
| SVC / IPC / memory / file tracers | existing `EDEN_NX2_SVC_TRACE`, `_IPC_TRACE`, `_IPC_SUMMARY`, `_MEM_TRACE`, `_FS_READ_TRACE` | Lines in the log. |
| Live debug server and GDB stub | `EDEN_NX2_DEBUG_SERVER`, `tools/nx2/gdbrsp.py` | Break on an address, read registers and memory (`docs/nx2/debug-mcp.md`). |
| Symbols and disassembly | `tools/nx2/nso_syms.py`, `nso_dis.py`, `npdm_info.py`, `a64_coverage.py` | Exports, GOT imports, instruction coverage per NSO. |
| Trace analysis | `tools/nx2/recomp/analyze_trace.py` | See below. |

## Workflow

```sh
tools/nx2/recomp/build-analysis.sh            # or build in a short path on Windows
tools/nx2/recomp/run-analysis.sh build-analysis/bin/eden-cli "<title>/exefs/main" out/orbitals
```

`run-analysis.sh` sets the tracers, runs the game, then runs `analyze_trace.py`. Results in
`out/orbitals/analysis`:

- `modules.json`: base, size, executed bytes per NSO (`rtld`, `main`, `sdk`, `subsdk*`).
- `blocks.json`: executed blocks as module-relative offsets. Offsets are stable across runs
  only if the NSO is the same build; they are what a recompiler maps to its own input.
- `functions.json`: function entry candidates with caller count, size and exported symbol.
- `indirect.json`: blocks ending in an indirect branch (vtables, jump tables). Their targets are
  unknown statically; collect more runs or break on them with the GDB stub to log the targets.
- `svc_ipc.json`: the SVCs and service commands the game needs. A recompiled build has to
  provide each one (a thin runtime that implements the same HLE calls).
- `report.md`: totals.

## Carrying it into a recompilation

1. Take the NSO from your own dump, decompress it (`nso_syms.load_image` does it), and use the
   exported symbols plus `functions.json` as function seeds.
2. Lift each function from the AArch64 bytes. Orbitals is a Switch 2 build, so the lifter must
   decode what stock decoders miss: PAC (RETAA/PACGA), LDAPR, LSE atomics, CAS/CASP, some FP16.
   `tools/nx2/a64_coverage.py` lists them per NSO.
3. Replace each SVC and IPC call with the runtime implementation listed in `svc_ipc.json`.
   Lichii's `src/core/hle` is the reference behaviour.
4. Resolve `indirect.json` entries (jump tables first) and re-run to extend coverage.
5. GPU work stays on the NVN2/Ampere path. `docs/nx2/gpu-trace.md` and `capture_frame` give the
   command streams to compare against.

## Limits

- Coverage is only what the run executed. Unplayed code is invisible.
- Function entries are heuristic (non-fallthrough link targets). Exported symbols are exact.
- The block tracer records blocks at compile time, not execution counts or call edges.
- Orbitals on Lichii must boot first. Check `docs/shader-sweep-all-games-20261104.md`: the
  Global Friends Pass entry notes that Unreal I/O Store (`.utoc`/`.ucas`) needs a selective reader.

## Getting a build and sending logs

- Build: the `analysis-build` workflow (Actions tab, "Run workflow", or any push to
  `analysis/recomp-build`) produces the artifact `lichii-analysis-windows-<sha>`: `eden-cli.exe`,
  PDBs and the `recomp/` scripts.
- Run on Windows: `.\recomp\run-analysis.ps1 -Game "<title>\exefs\main"` (needs Python 3 with
  numpy for `--exefs` symbol lookup). On Linux/macOS use `run-analysis.sh`.
- Logs: the run ends with two zips in the out folder. `lichii-logs-summary.zip` (a few MB: log
  digest, report, SVC/IPC list, top functions) is the one to send first.
  `lichii-logs-full.zip` holds the raw log and block trace. They contain no game files or keys;
  the full log can show file paths, so check it before sharing.

## Probing: the values orbitals-recomp has to reproduce

orbitals-recomp (pmocer-latibro) replaces SDK functions by name. Where its answer differs from the
console's, the game stalls (roadmap step 1: the RenderThread waits for ever after frame 21). Lichii
runs the game's own SDK, so its answers are the reference.

`run-probe.ps1` starts `eden-cli -d 6543` (the GDB stub; the game runs normally until a client
attaches) and `lichii-probe.exe`, which puts software breakpoints on the functions of a spec, logs
arguments, memory, return values, wait times, backtraces (as `main+0x...` with the nearest exported
symbol) and, optionally, which code writes an object (write watchpoint). Every probe has a hit limit:
each stop costs the game a few milliseconds.

`orbitals_blocker.json`, the default spec, targets the stall:

| Probe | Where | What it answers |
|---|---|---|
| `vi_GetLatestFrameNumber`, `vi_ListFrameHistory` | SDK entry points (by symbol, needs the exefs) | the real frame numbers and `FrameInfo` entries (40 bytes each) the SDK returns, which orbitals-recomp guesses today (`ov_gfx.c`) |
| `call_GetLatestFrameNumber`, `call_ListFrameHistory` | `main+0x153f990`, `main+0x1540460` (the BLs) | the same at the game's call sites, without symbols |
| `flip_tracker_wait` | `main+0x1540430`, BL to `WaitSystemEvent`, returns at `+0x1540434` | the event the flip tracker waits on and how long each wait lasts |
| `render_thread_wait` | `main+0x4a6d0`, BLR, returns at `+0x4a6d4` | the function the RenderThread calls, its object, and the code that writes that object (the signaller) |

Addresses come from the Lichii block traces: the roadmap's `main+0x4a6d4` and `main+0x1540434` are
the return addresses of these two calls. Output: `out-probe/probes_summary.txt` (short, attach it as
is) and `out-probe/probes.jsonl` (every event).
