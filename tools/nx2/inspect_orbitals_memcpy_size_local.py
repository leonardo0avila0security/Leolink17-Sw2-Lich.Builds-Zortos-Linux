#!/usr/bin/env python3
from pathlib import Path
import struct,zipfile,hashlib
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ZIP=Path("orbitals-recomp.zip")
FUNC=0x1B5A8470
def pe(data):
 p=struct.unpack_from("<I",data,0x3c)[0]
 if data[p:p+4]!=b"PE\0\0": raise ValueError("bad PE")
 n=struct.unpack_from("<H",data,p+6)[0]; os=struct.unpack_from("<H",data,p+20)[0]; opt=p+24
 base=struct.unpack_from("<Q",data,opt+24)[0]; sec=opt+os; ss=[]
 for i in range(n):
  o=sec+i*40; name=data[o:o+8].split(b"\0",1)[0].decode()
  vs,va,rs,rp=struct.unpack_from("<IIII",data,o+8); flags=struct.unpack_from("<I",data,o+36)[0]
  ss.append((name,va,max(vs,rs),rp,rs,flags))
 def off(rva,n=1):
  for name,va,extent,rp,rs,fl in ss:
   if va<=rva and rva+n<=va+extent and rva-va+n<=rs:return rp+rva-va
  return None
 return base,ss,off
with zipfile.ZipFile(ZIP) as z:
 name=next(x for x in z.namelist() if Path(x).name.lower()=="orbitalgame.dll")
 d=z.read(name)
base,sections,off=pe(d)
print("DLL_SIZE",len(d),"SHA256",hashlib.sha256(d).hexdigest(),"IMAGEBASE",hex(base))
for x in sections:
 if x[5]&0x20000000: print("EXEC",x[:5])
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def show(rva,n,label):
 o=off(rva,n)
 if o is None: print(label,"not raw-backed"); return
 print("\n==",label,"RVA",hex(rva),"file",hex(o),"==")
 for ins in md.disasm(d[o:o+n],base+rva):
  print(f"{ins.address-base:08x}: {ins.bytes.hex(' '):32} {ins.mnemonic:8} {ins.op_str}")
show(FUNC,0x180,"function entry/prologue")
o=off(FUNC,0x5000)
if o is None: raise SystemExit("function scan not raw-backed")
hits=[]
for ins in md.disasm(d[o:o+0x5000],base+FUNC):
 if "rbx - 0x98" in ins.op_str or "rbx-0x98" in ins.op_str:
  hits.append(ins.address-base)
print("\nRBX-0x98 REFERENCES",*[hex(x) for x in hits],sep="\n")
for r in hits:
 show(r-0x30,0x80,"local access context")
# Verify the already identified candidate cave only; do not scan the 500 MB .text byte-by-byte.
cave=0x1C7ED286; co=off(cave,0x17A)
print("\\nKNOWN_CAVE",hex(cave),"file",hex(co) if co is not None else "not-raw-backed",
      "all_int3",bool(co is not None and d[co:co+0x17A]==b"\\xCC"*0x17A))
