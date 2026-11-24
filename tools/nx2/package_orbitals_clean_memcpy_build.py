#!/usr/bin/env python3
"""Assemble a clean full Orbitals runtime folder with the patched game DLL.

This is a packaging step over the existing analysis-data runtime archive. It does
not run setup.py/prepare.py, regenerate guest code, or recompile the game.
"""
from pathlib import Path
import argparse, hashlib, zipfile

def sha(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda:f.read(8*1024*1024),b""):
            h.update(block)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",default="orbitals-recomp.zip")
    ap.add_argument("--patched-dll",default="orbitalgame.dll")
    ap.add_argument("--patch-report",default="orbitalgame.dll.patch-report.txt")
    ap.add_argument("--output",default="Orbitals-Recomp-Memcpy-Fix-Candidate.zip")
    ap.add_argument("--folder",default="Orbitals-Recomp-Memcpy-Fix-Candidate")
    a=ap.parse_args()
    source=Path(a.source); patched=Path(a.patched_dll); report=Path(a.patch_report)
    if not source.is_file() or not patched.is_file() or not report.is_file():
        raise SystemExit("Missing source archive, patched DLL, or patch report")
    dll_hash=sha(patched)
    matches=[]
    with zipfile.ZipFile(source,"r") as zin:
        for info in zin.infolist():
            if not info.is_dir() and Path(info.filename).name.lower()=="orbitalgame.dll":
                matches.append(info.filename)
        if len(matches)!=1:
            raise SystemExit(f"Expected exactly one orbitalgame.dll in source archive, found {matches}")
        dll_path=matches[0]
        # Write a clean folder tree, preserving the source archive's internal paths.
        with zipfile.ZipFile(a.output,"w",allowZip64=True) as zout:
            for info in zin.infolist():
                data=zin.read(info.filename)
                if info.filename==dll_path:
                    data=patched.read_bytes()
                zout.writestr(info,data)
            zout.writestr(a.folder+"/README-FIRST.txt",(
                "ORBITALS RECOMP — MEMCPY CRASH FIX CANDIDATE\n\n"
                "This is a complete runtime package assembled from the existing analysis-data build.\n"
                "The orbitalgame.dll inside the original runtime tree has been replaced by the\n"
                "version-locked candidate patch. All other files are preserved from the source archive.\n\n"
                "IMPORTANT: this candidate has not yet been validated in gameplay. Keep a backup of\n"
                "your previous folder. Extract this archive into a NEW, EMPTY folder. Do not merge\n"
                "it over an existing build.\n\n"
                "No setup.py, prepare.py, guest-code generation, or game recompilation was run.\n"
                "See PATCH-REPORT.txt for exact hashes and patch locations.\n"
            ).encode("utf-8"),compress_type=zipfile.ZIP_DEFLATED)
            zout.write(report,a.folder+"/PATCH-REPORT.txt")
            zout.writestr(a.folder+"/BUILD-MANIFEST.txt",(
                f"source_archive={source.name}\n"
                f"source_archive_sha256={sha(source)}\n"
                f"patched_orbitalgame_dll_sha256={dll_hash}\n"
                f"replaced_archive_path={dll_path}\n"
                "build_type=existing runtime repackaged with version-locked candidate DLL patch\n"
                "full_recompiler_build=no\n"
                "gameplay_validation=pending\n"
            ).encode("utf-8"),compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(a.output,"r") as z:
        bad=z.testzip()
        if bad: raise SystemExit(f"ZIP CRC verification failed: {bad}")
        names=z.namelist()
        if not any(n.endswith("/README-FIRST.txt") for n in names):
            raise SystemExit("README missing from package")
        # Confirm exactly one game DLL and it is byte-identical to the patched file.
        dll_entries=[n for n in names if Path(n).name.lower()=="orbitalgame.dll"]
        if len(dll_entries)!=1: raise SystemExit(f"Output DLL count mismatch: {dll_entries}")
        if z.read(dll_entries[0])!=patched.read_bytes():
            raise SystemExit("Packaged DLL differs from patched DLL")
    print("PACKAGE_OK=1")
    print(f"OUTPUT={Path(a.output).resolve()}")
    print(f"OUTPUT_SIZE={Path(a.output).stat().st_size}")
    print(f"OUTPUT_SHA256={sha(a.output)}")
    print(f"REPLACED_DLL_PATH={dll_path}")
    print(f"PATCHED_DLL_SHA256={dll_hash}")
    print("ZIP_CRC=OK")
    print("DLL_BYTES_MATCH=OK")
    print("SOURCE_FILES_PRESERVED=YES")
    print("RECOMPILATION=NOT_PERFORMED")

if __name__=="__main__": main()
