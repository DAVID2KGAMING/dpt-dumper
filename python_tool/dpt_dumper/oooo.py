"""Parser for the DPT 'Oooo' (MultiDexCode) file.

Layout (little endian):
  u16 version, u16 dex_count, u32 offsets[dex_count]
  per dex block: u16 method_count, then method_count x (u32 method_id, u32 size, bytes[size])
"""
import struct
from typing import Dict, List, Tuple


def parse_oooo(data: bytes) -> Tuple[int, List[dict]]:
    if len(data) < 8:
        return 0, []
    dex_count = struct.unpack_from("<H", data, 2)[0]
    pos = 4
    offsets = []
    for _ in range(dex_count):
        if pos + 4 > len(data):
            break
        offsets.append(struct.unpack_from("<I", data, pos)[0])
        pos += 4

    methods: List[dict] = []
    for dex_index, off in enumerate(offsets):
        if off + 2 > len(data):
            continue
        count = struct.unpack_from("<H", data, off)[0]
        p = off + 2
        for _ in range(count):
            if p + 8 > len(data):
                break
            mid, size = struct.unpack_from("<II", data, p)
            p += 8
            if p + size > len(data):
                break
            methods.append({"dex_index": dex_index, "method_id": mid,
                            "size": size, "code": data[p:p + size]})
            p += size
    return dex_count, methods


def build_blocks(methods: List[dict]) -> Dict[int, Dict[int, dict]]:
    blocks: Dict[int, Dict[int, dict]] = {}
    for m in methods:
        blocks.setdefault(m["dex_index"], {})[m["method_id"]] = m
    return blocks
