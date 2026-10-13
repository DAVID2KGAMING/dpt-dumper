import io
import os
import zipfile
from typing import Dict, List, Tuple

from . import dex as dexlib
from .oooo import build_blocks, parse_oooo
from .utils import ensure_dir, log, read_file, write_file


def verify_dex(data: bytes) -> bool:
    """Optional sanity check with Androguard (pip install androguard)."""
    try:
        try:
            from androguard.core.dex import DEX as _Dex  # androguard >= 4
        except ImportError:
            from androguard.core.bytecodes.dvm import DalvikVMFormat as _Dex
    except ImportError:
        log("androguard not installed; skipping --verify", "error")
        return True
    try:
        _Dex(data)
        return True
    except Exception:
        return False


def collect_dexes(input_path: str, work_dir: str) -> List[str]:
    """Return DEX paths: the file itself, or all *.dex extracted from an APK/zip."""
    data = read_file(input_path)
    if data.startswith(dexlib.DEX_MAGIC):
        return [input_path]

    start = data.find(b"PK\x03\x04")
    if start == -1:
        return []
    ensure_dir(work_dir)
    dexes: List[str] = []
    with zipfile.ZipFile(io.BytesIO(data[start:])) as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                z.extract(name, work_dir)  # zipfile sanitises unsafe paths
                dexes.append(os.path.join(work_dir, name))
    return dexes


def best_block(dex_map: Dict[int, dict], blocks: Dict[int, Dict[int, dict]]) -> Tuple[int, int]:
    """Pick the Oooo block whose method sizes overlap this DEX the most."""
    best_i, best_c = -1, 0
    for di, blk in blocks.items():
        c = sum(1 for mid, info in dex_map.items()
                if mid in blk and blk[mid]["size"] == info["size"])
        if c > best_c:
            best_i, best_c = di, c
    return best_i, best_c


def patch_dex(base: bytes, dex_map: Dict[int, dict], block: Dict[int, dict],
              verify: bool) -> Tuple[bytes, int]:
    data = bytearray(base)
    mids = [m for m, info in dex_map.items()
            if m in block and block[m]["size"] == info["size"]]
    log(f"Applying {len(mids)} patches (strict size match)", "debug")
    for mid in mids:
        info = dex_map[mid]
        off, size = info["offset"], info["size"]
        data[off:off + size] = block[mid]["code"]
    dexlib.fix_header(data)

    if verify and not verify_dex(bytes(data)):
        log("Verification failed after patching; writing unpatched copy.", "error")
        data = bytearray(base)
        dexlib.fix_header(data)
        return bytes(data), 0
    return bytes(data), len(mids)


def run(dex_input: str, oooo_path: str, out_dir: str, verify: bool = False) -> int:
    restored_dir = os.path.join(out_dir, "restored")
    ensure_dir(restored_dir)

    dexes = collect_dexes(input_path=dex_input, work_dir=os.path.join(out_dir, "extracted"))
    if not dexes:
        log("No DEX files found in input.", "error")
        return 1
    dexes = dexlib.dex_numeric_sort(dexes)
    log("DEX files: " + ", ".join(os.path.basename(d) for d in dexes), "debug")

    dex_count, methods = parse_oooo(read_file(oooo_path))
    if not methods:
        log("No methods parsed from Oooo file; nothing to patch.", "error")
        return 1
    log(f"Oooo: dex_count={dex_count}, methods={len(methods)}", "success")
    blocks = build_blocks(methods)

    produced = 0
    for path in dexes:
        name = os.path.basename(path)
        out_path = os.path.join(restored_dir, name)
        log(f"Processing {name}")
        base = read_file(path)

        def copy_only():
            buf = bytearray(base)
            dexlib.fix_header(buf)
            write_file(out_path, bytes(buf))

        try:
            dex_map, skipped = dexlib.map_methods(base)
        except Exception as e:
            log(f"DEX parse failed for {name}: {e}", "error")
            copy_only()
            produced += 1
            continue
        log(f"Mapped {len(dex_map)} methods (skipped {skipped} shared code_off)", "success")

        idx, overlap = best_block(dex_map, blocks)
        if idx < 0:
            log("No Oooo block matched (overlap=0); writing copy only.", "error")
            copy_only()
            produced += 1
            continue
        log(f"Aligned to Oooo dex_index={idx} (overlap={overlap})", "success")

        patched, applied = patch_dex(base, dex_map, blocks[idx], verify)
        write_file(out_path, patched)
        produced += 1
        log(f"Patched {applied} methods -> {out_path}", "success")

    log(f"Done. {produced} DEX file(s) in {restored_dir}", "success")
    return 0
