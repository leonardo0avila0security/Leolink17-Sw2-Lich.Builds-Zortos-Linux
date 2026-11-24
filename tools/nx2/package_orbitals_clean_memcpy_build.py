#!/usr/bin/env python3
"""Build a clean, setup-capable Orbitals folder from setup.zip + runtime ZIP.

The setup archive is the base so its NUP selection/preparation UI remains present.
The runtime archive overlays matching paths, with the patched orbitalgame.dll.
All files are placed under one top-level folder for clean extraction.
"""
from pathlib import Path
import argparse, hashlib, zipfile

def sha(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda:f.read(8*1024*1024),b""):
            h.update(block)
    return h.hexdigest()

def read_entries(path):
    result={}
    with zipfile.ZipFile(path,"r") as z:
        for info in z.infolist():
            if info.is_dir(): continue
            name=info.filename.replace("\\","/").lstrip("/")
            if not name or name.startswith("../") or "/../" in name:
                raise SystemExit(f"Unsafe archive path: {info.filename}")
            result[name]=(z.read(info.filename),info.compress_type)
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",default="orbitals-recomp.zip")
    ap.add_argument("--setup-source",default="setup.zip")
    ap.add_argument("--patched-dll",default="orbitalgame.dll")
    ap.add_argument("--patch-report",default="orbitalgame.dll.patch-report.txt")
    ap.add_argument("--output",default="Orbitals-Recomp-Memcpy-Fix-Setup-Candidate.zip")
    ap.add_argument("--folder",default="Orbitals-Recomp-Memcpy-Fix-Setup-Candidate")
    a=ap.parse_args()
    runtime=Path(a.source); setup=Path(a.setup_source)
    patched=Path(a.patched_dll); report=Path(a.patch_report)
    for f in (runtime,setup,patched,report):
        if not f.is_file(): raise SystemExit(f"Missing required input: {f}")
    # Setup first: retain its launcher, UI, NUP chooser and setup scripts.
    entries=read_entries(setup)
    setup_names=set(entries)
    runtime_entries=read_entries(runtime)
    dll_names=[n for n in runtime_entries if Path(n).name.lower()=="orbitalgame.dll"]
    if len(dll_names)!=1: raise SystemExit(f"Expected exactly one runtime DLL: {dll_names}")
    dll_name=dll_names[0]
    runtime_entries[dll_name]=(patched.read_bytes(),zipfile.ZIP_DEFLATED)
    overwritten=sorted(set(entries)&set(runtime_entries))
    entries.update(runtime_entries)
    # The launcher must actually be present; do not silently ship another runtime-only folder.
    launchers=[n for n in entries if Path(n).name.lower() in ("setup.exe","setup.py","setup.bat","setup.cmd")]
    if not launchers:
        raise SystemExit("setup.zip contains no recognizable setup launcher (setup.exe/.py/.bat/.cmd); refusing to publish")
    # At least one NUP selection/configuration component should exist in setup archive.
    setup_candidates=[n for n in setup_names if any(k in Path(n).name.lower() for k in ("setup","nup","select","picker"))]
    if not setup_candidates:
        raise SystemExit("setup.zip has no recognizable setup/NUP-selection files; inspect archive before packaging")
    out=Path(a.output)
    with zipfile.ZipFile(out,"w",allowZip64=True) as z:
        for name,(data,ctype) in sorted(entries.items()):
            z.writestr(a.folder+"/"+name,data,compress_type=ctype)
        z.writestr(a.folder+"/README-FIRST.txt",(
            "ORBITALS RECOMP — SETUP + MEMCPY FIX CANDIDATE\n\n"
            "This clean package combines the original setup archive (including its setup/NUP selection UI)\n"
            "with the existing runtime archive. The runtime's orbitalgame.dll is replaced by the\n"
            "version-locked candidate patch. Runtime files take precedence for duplicate paths.\n\n"
            "Extract the complete archive into a NEW, EMPTY folder. Start the original setup launcher\n"
            "to select the .nup and prepare the game. After setup, launch orbitals-recomp.exe.\n\n"
            "The candidate DLL has not yet been validated in gameplay. Keep your previous build.\n"
            "No setup/prepare/recompile operation was run during creation of this package.\n"
        ).encode(),compress_type=zipfile.ZIP_DEFLATED)
        z.write(report,a.folder+"/PATCH-REPORT.txt",compress_type=zipfile.ZIP_DEFLATED)
        z.writestr(a.folder+"/BUILD-MANIFEST.txt",(
            f"setup_archive={setup.name}\nsetup_archive_sha256={sha(setup)}\n"
            f"runtime_archive={runtime.name}\nruntime_archive_sha256={sha(runtime)}\n"
            f"patched_orbitalgame_dll_sha256={sha(patched)}\n"
            f"runtime_dll_path={dll_name}\n"
            f"setup_launchers={';'.join(launchers)}\n"
            f"setup_nup_files={';'.join(sorted(setup_candidates)[:100])}\n"
            f"overwritten_duplicate_paths={';'.join(overwritten)}\n"
            "package_type=setup-capable clean full runtime folder\n"
            "game_recompilation=not performed\ngameplay_validation=pending\n"
        ).encode(),compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(out) as z:
        bad=z.testzip()
        if bad: raise SystemExit(f"ZIP CRC failed: {bad}")
        names=z.namelist()
        root=a.folder+"/"
        if not any(n.startswith(root) and Path(n).name.lower() in ("setup.exe","setup.py","setup.bat","setup.cmd") for n in names):
            raise SystemExit("Packaged setup launcher missing")
        dlls=[n for n in names if n.startswith(root) and Path(n).name.lower()=="orbitalgame.dll"]
        if len(dlls)!=1 or z.read(dlls[0])!=patched.read_bytes():
            raise SystemExit(f"Patched DLL verification failed: {dlls}")
    print("PACKAGE_OK=1")
    print(f"OUTPUT={out.resolve()}")
    print(f"OUTPUT_SIZE={out.stat().st_size}")
    print(f"OUTPUT_SHA256={sha(out)}")
    print(f"SETUP_LAUNCHERS={launchers}")
    print(f"SETUP_NUP_FILES={setup_candidates[:50]}")
    print(f"OVERWRITTEN_DUPLICATES={overwritten}")
    print(f"PATCHED_DLL_SHA256={sha(patched)}")
    print("ZIP_CRC=OK")
    print("SETUP_LAUNCHER=OK")
    print("PATCHED_DLL_BYTES_MATCH=OK")
    print("RECOMPILATION=NOT_PERFORMED")

if __name__=="__main__": main()
