#!/usr/bin/env python3
"""Reconstruct the live guest branch and the size local for dump 16952.

Important: x29 and x24 are read from the hostfn context snapshot. The saved
callee-register slots in the AArch64 frame are not substituted for live regs.
"""
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
  x29=q(f,rs,ctxp+0xe8); x24=q(f,rs,ctxp+0xc0)
  x23_saved=q(f,rs,sp+0xf8); x24_saved=q(f,rs,sp+0xf0)
  x21=q(f,rs,ctxp+0xa8); x27=q(f,rs,ctxp+0xd8)
  w12_ctx=u32(f,rs,ctxp+0x60); w12_stack=u32(f,rs,sp+0x4c)
  print(f"dump={fs} context={ctxp:#x} pre_sp={pre:#x} active_sp={sp:#x}")
  print(f"live_x21={hx(x21)} live_x27={hx(x27)} live_x29={hx(x29)} live_x24={hx(x24)}")
  print(f"saved_x23={hx(x23_saved)} saved_x24={hx(x24_saved)} w12_ctx={hx(w12_ctx)} w12_stack_local={hx(w12_stack)}")
  p_x29=q(f,rs,x29-8) if x29 else None
  print(f"[live_x29-8]={hx(p_x29)}")
  idx=x24
  a2=(p_x29+idx*8) if p_x29 is not None and idx is not None else None
  w9raw=u32(f,rs,a2) if a2 is not None else None
  print(f"live_loop_index={hx(idx)} index_addr={hx(a2)} w9_raw={hx(w9raw)} w9_signed={s32(w9raw) if w9raw is not None else None}")
  if x21 is not None and x27 is not None:
   arr=q(f,rs,x21+0x158); count=u32(f,rs,x21+0x160)
   print(f"table_base={hx(arr)} table_count={hx(count)}")
   delta=(x27-arr) if arr is not None else None
   print(f"record_delta={hx(delta)} record_index={(delta//0xe8 if delta is not None and delta%0xe8==0 else 'not-stride-aligned')}")
   d0=q(f,rs,x27+0xd0); d8raw=u32(f,rs,x27+0xd8); d8=s32(d8raw) if d8raw is not None else None
   base=d0 if d0 else x27+0x10
   eff=(base+(d8<<6)) if d8 is not None else None
   would_load=eff-8 if eff is not None else None
   local=q(f,rs,sp+0x88)
   print(f"record+0xd0={hx(d0)} +0xd8_raw={hx(d8raw)} signed={d8}")
   print(f"selected_base={hx(base)} x8_effective={hx(eff)} would_be_load_addr={hx(would_load)}")
   print(f"stack_local_sp+0x88={hx(local)} (used later by ldrsw)")
   # The load/store at 0x1759e54 is conditional. Reconstruct its gate.
   less=(s32(w9raw)<d8) if w9raw is not None and d8 is not None else None
   flag=(w12_ctx&1) if w12_ctx is not None else None
   gate=(less and flag==1) if less is not None and flag is not None else None
   print(f"branch_cmp_signed_w9_lt_w8={less} w12_bit0={flag} load_store_gate={gate}")
   if gate is False: print("RESULT: branch skips ldur d0 / str [sp+0x88]; existing stack local survives into later size use.")
   elif gate is True: print("RESULT: branch executes ldur d0 / str [sp+0x88].")
   else: print("RESULT: branch gate unresolved from captured registers.")
   if would_load is not None:
    print("would-be-load neighborhood (snapshot is after any later store):")
    for off in range(-0x20,0x21,8): print(f"  {would_load+off:#x}: {hx(q(f,rs,would_load+off))}")
  print("stack locals:")
  for off in (0x2c,0x30,0x34,0x38,0x4c,0x80,0x88,0x90,0xa0,0xa8,0xb0,0xc0,0xd0,0xd8,0xe0,0xf0,0xf8):
   print(f"  sp+{off:#x}={hx(q(f,rs,sp+off))}")
if __name__=="__main__":
 if len(sys.argv)!=2: raise SystemExit("usage: probe_orbitals_memcpy_branch_exact.py dump.dmp")
 main(sys.argv[1])
