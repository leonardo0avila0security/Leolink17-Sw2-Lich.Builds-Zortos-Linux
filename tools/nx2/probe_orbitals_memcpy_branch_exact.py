#!/usr/bin/env python3
"""Reconstruct the exact branch inputs and effective size-field load for dump 16952."""
import struct,sys
def parse(f):
 f.seek(0,2); fs=f.tell(); f.seek(0)
 if f.read(4)!=b"MDMP": raise ValueError("not MDMP")
 f.seek(8); n=struct.unpack("<I",f.read(4))[0]; d=struct.unpack("<I",f.read(4))[0]; streams={}
 for i in range(n):
  f.seek(d+i*12); t,s,r=struct.unpack("<III",f.read(12)); streams[t]=(s,r)
 rs=[]
 if 9 in streams:
  s,r=streams[9]; f.seek(r); n,p=struct.unpack("<QQ",f.read(16))
  for _ in range(n):
   a,z=struct.unpack("<QQ",f.read(16))
   if z and p+z<=fs: rs.append((a,z,p))
   p+=z
 if 5 in streams:
  s,r=streams[5]; f.seek(r); n=struct.unpack("<I",f.read(4))[0]
  for _ in range(n):
   a,z,o=struct.unpack("<QII",f.read(16))
   if z and o+z<=fs: rs.append((a,z,o))
 return sorted(rs),fs,streams
def read(f,rs,a,n):
 out=bytearray(); p=a
 while p<a+n:
  hits=[x for x in rs if x[0]<=p<x[0]+x[1]]
  if not hits:return None
  b,z,o=max(hits,key=lambda x:x[0]+x[1]); k=min(a+n,b+z)-p
  f.seek(o+p-b); q=f.read(k)
  if len(q)!=k:return None
  out.extend(q);p+=k
 return bytes(out)
def q(f,rs,a):
 b=read(f,rs,a,8); return struct.unpack("<Q",b)[0] if b else None
def u32(f,rs,a):
 b=read(f,rs,a,4); return struct.unpack("<I",b)[0] if b else None
def s32(v): return struct.unpack("<i",struct.pack("<I",v&0xffffffff))[0]
def hx(v): return "not-captured" if v is None else f"{v:#x}"
def main(path):
 with open(path,"rb") as f:
  rs,fs,st=parse(f); _,er=st[6]; f.seek(er+164); cr=struct.unpack("<I",f.read(4))[0]; f.seek(cr+168); ctxp=struct.unpack("<Q",f.read(8))[0]
  ctx=read(f,rs,ctxp,0x400)
  if not ctx: raise SystemExit("host context not captured")
  pre=q(f,rs,ctxp+0x100); sp=pre-0x120
  x29=q(f,rs,sp+0xc0); x23=q(f,rs,sp+0xf8); x24=q(f,rs,sp+0xf0)
  x21=q(f,rs,ctxp+0xa8); x27=q(f,rs,ctxp+0xd8)
  print(f"dump={fs} context={ctxp:#x} pre_sp={pre:#x} active_sp={sp:#x}")
  print(f"x21(candidate)={hx(x21)} x27(snapshot)={hx(x27)} x29={hx(x29)} x23(saved)={hx(x23)} x24(saved)={hx(x24)}")
  w12=u32(f,rs,sp+0x4c); print(f"w12_local_[sp+0x4c]={hx(w12)}")
  p_x29=q(f,rs,x29-8) if x29 else None
  print(f"[x29-8]={hx(p_x29)}")
  if x24 is None: raise SystemExit("x24 not captured")
  idx=x24
  a1=(x23+idx*8) if x23 is not None else None
  a2=(p_x29+idx*8) if p_x29 is not None else None
  w20raw=u32(f,rs,a1+4) if a1 is not None else None
  w9raw=u32(f,rs,a2) if a2 is not None else None
  print(f"loop_x24={idx:#x} x23_pair_addr={hx(a1)} w20_raw={hx(w20raw)} w20_signed={s32(w20raw) if w20raw is not None else None}")
  print(f"x29_array_addr={hx(a2)} w9_raw={hx(w9raw)} w9_signed={s32(w9raw) if w9raw is not None else None}")
  if x21 is not None and w20raw is not None:
   arr=q(f,rs,x21+0x158); count=u32(f,rs,x21+0x160)
   print(f"table_base={hx(arr)} table_count={hx(count)}")
   rec=arr+s32(w20raw)*0xe8 if arr is not None else None
   print(f"selected_record={hx(rec)} expected_x27_snapshot={hx(x27)} record_matches={rec==x27 if rec is not None and x27 is not None else None}")
   if rec is not None:
    d0=q(f,rs,rec+0xd0); d8raw=u32(f,rs,rec+0xd8); d8=s32(d8raw) if d8raw is not None else None
    base=d0 if d0 else rec+0x10
    eff=(base+(d8<<6)) if d8 is not None else None
    load=eff-8 if eff is not None else None
    before_local=q(f,rs,sp+0x88)
    after=q(f,rs,load) if load is not None else None
    print(f"record+0xd0={hx(d0)} +0xd8_raw={hx(d8raw)} signed={d8}")
    print(f"selected_base={hx(base)} x8_effective={hx(eff)} load_addr=[x8-8]={hx(load)}")
    print(f"captured_qword_at_load(after_store)={hx(after)} saved_d0_local_[sp+0x88]={hx(before_local)}")
    if load is not None:
     print("load_neighborhood:")
     for off in range(-0x20,0x21,8): print(f"  {load+off:#x}: {hx(q(f,rs,load+off))}")
  print("stack branch locals:")
  for off in (0x2c,0x30,0x34,0x38,0x4c,0x80,0x88,0xb0):
   print(f"  sp+{off:#x}={hx(q(f,rs,sp+off))}")
if __name__=="__main__":
 if len(sys.argv)!=2: raise SystemExit("usage: probe_orbitals_memcpy_branch_exact.py dump.dmp")
 main(sys.argv[1])
