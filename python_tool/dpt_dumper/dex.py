"""Minimal DEX parsing: class_data -> encoded_method -> code_item."""
import hashlib
import os
import re
import struct
import zlib
from typing import Dict, List, Tuple

DEX_MAGIC = b"dex\n"


def dex_number_from_name(path: str) -> int:
    """classes.dex -> 0, classes2.dex -> 1, ... ; -1 if not a classesN.dex name."""
    m = re.match(r"^classes(\d*)\.dex$", os.path.basename(path))
    if not m:
        return -1
    return 0 if not m.group(1) else int(m.group(1)) - 1


def dex_numeric_sort(paths: List[str]) -> List[str]:
    def key(p: str):
        n = dex_number_from_name(p)
        return (n if n >= 0 else 10**9, os.path.basename(p))

    return sorted(paths, key=key)


def fix_header(buf: bytearray) -> None:
    """Recompute file_size, SHA-1 signature and Adler-32 checksum in place."""
    buf[0x20:0x24] = struct.pack("<I", len(buf))
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    buf[8:12] = struct.pack("<I", zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)


def uleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = shift = 0
    while True:
        if off >= len(data):
            raise ValueError("uleb128 runs past end of file")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 too long")


class DexHeader:
    def __init__(self, buf: bytes):
        if len(buf) < 0x70 or not buf.startswith(DEX_MAGIC):
            raise ValueError("not a DEX file")
        self.class_defs_size = struct.unpack_from("<I", buf, 0x60)[0]
        self.class_defs_off = struct.unpack_from("<I", buf, 0x64)[0]


def map_methods(buf: bytes) -> Tuple[Dict[int, dict], int]:
    """Map method_idx -> {code_off, offset (insns start), size (bytes)}.

    Methods that share one code_off are skipped (ambiguous to patch).
    Returns (mapping, number_skipped).
    """
    hdr = DexHeader(buf)
    found: Dict[int, Tuple[int, int, int]] = {}
    freq: Dict[int, int] = {}

    off = hdr.class_defs_off
    for _ in range(hdr.class_defs_size):
        class_data_off = struct.unpack_from("<I", buf, off + 24)[0]
        off += 32
        if class_data_off == 0:
            continue

        p = class_data_off
        static_f, p = uleb128(buf, p)
        inst_f, p = uleb128(buf, p)
        direct_m, p = uleb128(buf, p)
        virtual_m, p = uleb128(buf, p)

        for _ in range(static_f + inst_f):
            _, p = uleb128(buf, p)  # field_idx_diff
            _, p = uleb128(buf, p)  # access_flags

        for count in (direct_m, virtual_m):
            idx = 0
            for _ in range(count):
                diff, p = uleb128(buf, p)
                idx += diff
                _, p = uleb128(buf, p)  # access_flags
                code_off, p = uleb128(buf, p)
                if code_off == 0 or code_off + 16 > len(buf):
                    continue
                insns_units = struct.unpack_from("<I", buf, code_off + 12)[0]
                size = insns_units * 2
                insns_off = code_off + 16
                if size <= 0 or insns_off + size > len(buf):
                    continue
                found[idx] = (code_off, insns_off, size)
                freq[code_off] = freq.get(code_off, 0) + 1

    out: Dict[int, dict] = {}
    skipped = 0
    for idx, (code_off, insns_off, size) in found.items():
        if freq[code_off] > 1:
            skipped += 1
            continue
        out[idx] = {"code_off": code_off, "offset": insns_off, "size": size}
    return out, skipped
