package com.david2k.dptdumper.core;

import java.util.HashMap;
import java.util.Map;

/**
 * Parser for the DPT "Oooo" (MultiDexCode) file. Little endian:
 *   u16 version, u16 dex_count, u32 offsets[dex_count]
 *   per dex block: u16 method_count, then (u32 method_id, u32 size, bytes[size]) x method_count
 */
public final class OoooParser {
    public int dexCount;
    public int methodCount;
    /** dex_index -> (method_id -> code bytes) */
    public final Map<Integer, Map<Integer, byte[]>> blocks = new HashMap<>();

    public static OoooParser parse(byte[] d) {
        OoooParser r = new OoooParser();
        if (d.length < 8) return r;
        r.dexCount = DexUtil.u16(d, 2);
        int pos = 4;
        int[] offs = new int[r.dexCount];
        int n = 0;
        for (int i = 0; i < r.dexCount; i++) {
            if (pos + 4 > d.length) break;
            offs[n++] = (int) DexUtil.u32(d, pos);
            pos += 4;
        }
        for (int dexIndex = 0; dexIndex < n; dexIndex++) {
            int o = offs[dexIndex];
            if (o < 0 || o + 2 > d.length) continue;
            int count = DexUtil.u16(d, o);
            int p = o + 2;
            for (int k = 0; k < count; k++) {
                if (p + 8 > d.length) break;
                int mid = (int) DexUtil.u32(d, p);
                long size = DexUtil.u32(d, p + 4);
                p += 8;
                if (size < 0 || p + size > d.length) break;
                byte[] code = new byte[(int) size];
                System.arraycopy(d, p, code, 0, (int) size);
                p += (int) size;
                Map<Integer, byte[]> blk = r.blocks.get(dexIndex);
                if (blk == null) { blk = new HashMap<>(); r.blocks.put(dexIndex, blk); }
                blk.put(mid, code);
                r.methodCount++;
            }
        }
        return r;
    }
}
