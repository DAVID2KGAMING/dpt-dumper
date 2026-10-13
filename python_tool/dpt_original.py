#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPT DEX RESTORER – FAST / STABLE
=================================
- Spec-correct DEX parser (class_data → encoded_method → code_off)
- Skip duplicate code_off methods (like DexUtils.saveCodeOffAppear)  fileciteturn0file1
- Strict size equality by default (prevents wrong patch)
- Best-overlap auto-align for Oooo (dex_index)
- Single-pass patch (progress logs) + header fix
- Optional Androguard verification via --verify (off by default for speed)

Usage:
  python dpt.py <classes.dex or apk> <Oooo file> <out_dir>
  python dpt.py classes.dex OoooooOooo out/

If the first arg contains an embedded ZIP (APK/AAB), dex files are extracted.

References from your Java sources:
- DexUtils.restoreInstructions: write at code_off + 16 with full insns length  fileciteturn0file1
- MultiDexCodeUtils layout for Oooo (methodId, size, raw bytes)             fileciteturn0file7
Made by Its_PokemonZ
"""

import os, sys, re, struct, zipfile, io, hashlib, zlib
from typing import Dict, List, Tuple

# -------- Optional verify (Androguard) --------
VERIFY = False
try:
    from androguard.core.bytecodes.dvm import DalvikVMFormat  # type: ignore
    ANDRO_OK = True
except Exception:
    ANDRO_OK = False

def enable_verify(flag: bool):
    global VERIFY
    VERIFY = bool(flag and ANDRO_OK)

# -------- Logging --------
def log(msg: str, lvl: str="info"):
    p = {"info":"[*]","success":"[✓]","error":"[!]","debug":"[DEBUG]"}.get(lvl,"[*]")
    print(f"{p} {msg}", flush=True)

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def read_file(p: str) -> bytes:
    with open(p,"rb") as f: return f.read()

def write_file(p: str, d: bytes):
    ensure_dir(os.path.dirname(p) or ".")
    with open(p,"wb") as f: f.write(d)

# -------- DEX helpers --------
def dex_number_from_name(path: str) -> int:
    name = os.path.basename(path)
    m = re.match(r"^classes(\d*)\.dex$", name)
    if not m: return -1
    s = m.group(1)
    if not s: return 0
    try: return int(s)-1
    except: return -1

def dex_numeric_sort(paths: List[str]) -> List[str]:
    return sorted(paths, key=lambda p: (dex_number_from_name(p) if dex_number_from_name(p) >= 0 else 10**9, os.path.basename(p)))

def fix_dex_header_inplace(d: bytearray):
    d[0x20:0x24] = struct.pack("<I", len(d))
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    d[8:12]  = struct.pack("<I", zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF)

def return_void_padding(nbytes: int) -> bytes:
    if nbytes <= 0: return b""
    return (b"\x0e\x00" * ((nbytes+1)//2))[:nbytes]

# -------- Oooo parser (MultiDexCode) --------  fileciteturn0file7
def parse_oooo(path: str) -> Tuple[int, List[dict]]:
    d = read_file(path)
    if len(d) < 8: return 0, []
    dex_count = struct.unpack("<H", d[2:4])[0]
    pos = 4
    offs = []
    for _ in range(dex_count):
        if pos+4 > len(d): break
        offs.append(struct.unpack("<I", d[pos:pos+4])[0])
        pos += 4
    methods = []
    for dex_i, o in enumerate(offs):
        if o+2 > len(d): continue
        mc = struct.unpack("<H", d[o:o+2])[0]
        p2 = o+2
        for _ in range(mc):
            if p2+8 > len(d): break
            mid, size = struct.unpack("<II", d[p2:p2+8]); p2 += 8
            if p2+size > len(d): break
            code = d[p2:p2+size]; p2 += size
            methods.append({"dex_index":int(dex_i),"method_id":int(mid),"size":int(size),"code":code})
    return dex_count, methods

# -------- DEX spec parser (class_data → encoded_method → code_off) --------  fileciteturn0file1
def uleb128(data: bytes, off: int) -> Tuple[int,int]:
    res=0; sh=0
    while True:
        b=data[off]; off+=1
        res |= (b & 0x7F) << sh
        if (b & 0x80)==0: break
        sh+=7
        if sh>35: raise ValueError("uleb128 too big")
    return res, off

class DexHeader:
    def __init__(self, buf: bytes):
        if len(buf) < 0x70 or not buf[:8].startswith(b"dex\n"):
            raise ValueError("Not a dex file")
        def u32(o): return struct.unpack_from("<I", buf, o)[0]
        self.class_defs_size = u32(0x60)
        self.class_defs_off  = u32(0x64)

def analyze_dex_spec_with_dupe_skip(buf: bytes) -> Tuple[Dict[int,dict], int]:
    hdr = DexHeader(buf)
    tmp = {}          # mid -> (code_off, insns_off, cap)
    count = {}        # code_off -> freq

    off = hdr.class_defs_off
    for _ in range(hdr.class_defs_size):
        class_data_off = struct.unpack_from("<I", buf, off+24)[0]
        off += 32
        if class_data_off == 0: continue
        p = class_data_off

        sfs,p = uleb128(buf,p)
        ifs,p = uleb128(buf,p)
        dms,p = uleb128(buf,p)
        vms,p = uleb128(buf,p)

        for _ in range(sfs): _,p=uleb128(buf,p); _,p=uleb128(buf,p)
        for _ in range(ifs): _,p=uleb128(buf,p); _,p=uleb128(buf,p)

        def read_methods(n):
            nonlocal p
            mid_acc=0
            for _ in range(n):
                diff,p = uleb128(buf,p); mid_acc += diff
                _,p = uleb128(buf,p)          # access_flags
                code_off,p = uleb128(buf,p)
                if code_off==0 or code_off+16>len(buf): continue
                ins_units = struct.unpack_from("<I", buf, code_off+12)[0]
                cap = int(ins_units)*2
                ins_off = int(code_off)+16
                if cap<=0 or ins_off+cap>len(buf): continue
                tmp[mid_acc] = (int(code_off), ins_off, cap)
                count[int(code_off)] = count.get(int(code_off), 0)+1

        read_methods(dms)
        read_methods(vms)

    out={}; skipped=0
    for mid,(co,ioff,cap) in tmp.items():
        if count.get(co,0)>1:   # skip shared code_off like Java  fileciteturn0file1
            skipped+=1; continue
        out[mid]={"code_off":co,"offset":ioff,"size":cap}
    return out, skipped

def validate_with_androguard(d: bytes) -> bool:
    if not VERIFY or not ANDRO_OK: return True
    try:
        DalvikVMFormat(d)  # type: ignore
        return True
    except Exception:
        return False

# -------- Core Restorer --------
def extract_embedded_zip_dexes(input_path: str, out_dir: str) -> List[str]:
    data = read_file(input_path)
    off = data.find(b"PK\x03\x04")
    if off == -1: return []
    ensure_dir(out_dir)
    z = zipfile.ZipFile(io.BytesIO(data[off:]))
    z.extractall(out_dir)
    dexes=[]
    for r,_,fs in os.walk(out_dir):
        for fn in fs:
            if fn.endswith(".dex"):
                dexes.append(os.path.join(r,fn))
    return dexes

def build_oooo_blocks(methods: List[dict]) -> Dict[int, Dict[int, dict]]:
    blocks={}
    for m in methods:
        di = int(m["dex_index"]); mid = int(m["method_id"])
        blocks.setdefault(di,{})[mid]=m
    return blocks

def best_match_block(dex_map: Dict[int,dict], blocks: Dict[int,Dict[int,dict]]) -> Tuple[int,int]:
    best_i=-1; best_c=0
    for di,blk in blocks.items():
        c=0
        for mid,info in dex_map.items():
            o=blk.get(mid)
            if not o: continue
            if o["size"]==info["size"]:
                c+=1
        if c>best_c: best_c=c; best_i=di
    return best_i,best_c

def patch_one_dex(base: bytes, dex_map: Dict[int,dict], oooo_block: Dict[int,dict]) -> Tuple[bytes,int,int]:
    data = bytearray(base)
    mids=[mid for mid,info in dex_map.items() if mid in oooo_block and oooo_block[mid]["size"]==info["size"]]
    total=len(mids)
    log(f"Preparing {total} patches (strict size equal)")

    attempted=0
    for idx, mid in enumerate(mids,1):
        info=dex_map[mid]; o=oooo_block[mid]
        off=int(info["offset"]); cap=int(info["size"]); src=bytes(o["code"])
        attempted+=1
        if len(src)!=cap:  # safety
            continue
        data[off:off+cap]=src
        if idx % 1000 == 0 or idx == total:
            log(f"  applied {idx}/{total}", "debug")

    fix_dex_header_inplace(data)

    if not validate_with_androguard(bytes(data)):
        log("Androguard validation failed after patch; writing copy with hashes only.", "error")
        data = bytearray(base); fix_dex_header_inplace(data); return bytes(data), 0, attempted

    return bytes(data), attempted, attempted  # applied==attempted in strict mode

def run(dex_input: str, oooo_path: str, out_dir: str, verify: bool=False):
    enable_verify(verify)
    ensure_dir(out_dir)
    exdir=os.path.join(out_dir,"extracted"); redir=os.path.join(out_dir,"restored")
    ensure_dir(redir)

    dexes = extract_embedded_zip_dexes(dex_input, exdir)
    if not dexes: dexes=[dex_input]
    dexes=dex_numeric_sort(dexes)
    log("DEX files: " + ", ".join(os.path.basename(x) for x in dexes), "debug")

    dcount, methods = parse_oooo(oooo_path)
    if not methods:
        log("No methods parsed from Oooo file; nothing to patch.","error"); return
    log(f"Oooo dex_count={dcount}, parsed_methods={len(methods)}","success")
    blocks=build_oooo_blocks(methods)

    produced=0
    for dx in dexes:
        name=os.path.basename(dx)
        log(f"Processing {name}")

        base=read_file(dx)
        try:
            dex_map, skipped = analyze_dex_spec_with_dupe_skip(base)
        except Exception as e:
            log(f"DEX parse failed: {name} ({e})","error")
            out_path=os.path.join(redir,name); data=bytearray(base); fix_dex_header_inplace(data); write_file(out_path,bytes(data)); produced+=1; continue

        log(f"Mapped={len(dex_map)} methods (skipped dup code_off={skipped})","success")

        best_i,best_c = best_match_block(dex_map, blocks)
        if best_i<0 or best_c==0:
            log("No suitable Oooo block matched (overlap=0). Output copy only.","error")
            out_path=os.path.join(redir,name); data=bytearray(base); fix_dex_header_inplace(data); write_file(out_path,bytes(data)); produced+=1; continue

        log(f"Auto-aligned to Oooo dex_index={best_i} (overlap={best_c})","success")

        patched, applied, attempted = patch_one_dex(base, dex_map, blocks[best_i])
        out_path=os.path.join(redir,name); write_file(out_path, patched); produced+=1
        log(f"Patched applied={applied}/{attempted} → {out_path}","success")

    log(f"Done. Produced {produced} dex file(s) in: {redir}","success")

def main():
    args=[a for a in sys.argv[1:] if a!="--verify"]
    verify = ("--verify" in sys.argv[1:])
    if len(args)!=3:
        print("Usage: python dpt.py <classes.dex|apk> <Oooo file> <out_dir> [--verify]")
        sys.exit(2)
    run(args[0], args[1], args[2], verify=verify)

if __name__=="__main__":
    main()
