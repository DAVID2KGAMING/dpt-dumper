package com.david2k.dptdumper.core;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.Adler32;

/** Minimal DEX parsing: class_data -> encoded_method -> code_item. */
public final class DexUtil {
    private DexUtil() {}

    /** Location of one method's instructions inside the DEX. */
    public static final class Method {
        public final int codeOff, insnsOff, size;
        Method(int codeOff, int insnsOff, int size) {
            this.codeOff = codeOff; this.insnsOff = insnsOff; this.size = size;
        }
    }

    public static final class MapResult {
        public final Map<Integer, Method> methods;
        public final int skipped;
        MapResult(Map<Integer, Method> m, int s) { methods = m; skipped = s; }
    }

    public static long u32(byte[] b, int o) {
        return (b[o] & 0xFFL) | ((b[o + 1] & 0xFFL) << 8) | ((b[o + 2] & 0xFFL) << 16) | ((b[o + 3] & 0xFFL) << 24);
    }

    public static int u16(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
    }

    static void putU32(byte[] b, int o, long v) {
        b[o] = (byte) v; b[o + 1] = (byte) (v >> 8); b[o + 2] = (byte) (v >> 16); b[o + 3] = (byte) (v >> 24);
    }

    public static boolean isDex(byte[] b) {
        return b.length >= 0x70 && b[0] == 'd' && b[1] == 'e' && b[2] == 'x' && b[3] == '\n';
    }

    /** classes.dex -> 0, classes2.dex -> 1 ... ; -1 when not a classesN.dex name. */
    public static int dexNumber(String name) {
        String base = name.substring(name.lastIndexOf('/') + 1);
        if (!base.startsWith("classes") || !base.endsWith(".dex")) return -1;
        String mid = base.substring(7, base.length() - 4);
        if (mid.isEmpty()) return 0;
        try { return Integer.parseInt(mid) - 1; } catch (NumberFormatException e) { return -1; }
    }

    /** Recompute file_size, SHA-1 signature and Adler-32 checksum in place. */
    public static void fixHeader(byte[] d) {
        putU32(d, 0x20, d.length);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(d, 32, d.length - 32);
            System.arraycopy(md.digest(), 0, d, 12, 20);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        Adler32 ad = new Adler32();
        ad.update(d, 12, d.length - 12);
        putU32(d, 8, ad.getValue());
    }

    private static long uleb(byte[] b, int[] pos) throws IOException {
        long result = 0;
        int shift = 0;
        while (true) {
            if (pos[0] >= b.length) throw new IOException("uleb128 runs past end of file");
            int x = b[pos[0]++] & 0xFF;
            result |= (long) (x & 0x7F) << shift;
            if ((x & 0x80) == 0) return result;
            shift += 7;
            if (shift > 35) throw new IOException("uleb128 too long");
        }
    }

    /**
     * Map method_idx -> instruction location. Methods sharing one code_off are
     * skipped (ambiguous to patch), like the original tool.
     */
    public static MapResult mapMethods(byte[] buf) throws IOException {
        if (!isDex(buf)) throw new IOException("Not a DEX file");
        long classDefsSize = u32(buf, 0x60);
        long off = u32(buf, 0x64);

        Map<Integer, Method> found = new LinkedHashMap<>();
        Map<Integer, Integer> freq = new HashMap<>();

        for (long i = 0; i < classDefsSize; i++) {
            if (off + 32 > buf.length) throw new IOException("class_defs out of range");
            long classDataOff = u32(buf, (int) off + 24);
            off += 32;
            if (classDataOff == 0) continue;
            if (classDataOff >= buf.length) throw new IOException("class_data out of range");

            int[] p = {(int) classDataOff};
            long staticF = uleb(buf, p), instF = uleb(buf, p);
            long direct = uleb(buf, p), virtual = uleb(buf, p);
            for (long k = 0; k < staticF + instF; k++) { uleb(buf, p); uleb(buf, p); }

            for (long count : new long[]{direct, virtual}) {
                int idx = 0;
                for (long k = 0; k < count; k++) {
                    idx += (int) uleb(buf, p);
                    uleb(buf, p); // access_flags
                    long codeOff = uleb(buf, p);
                    if (codeOff == 0 || codeOff + 16 > buf.length) continue;
                    long size = u32(buf, (int) codeOff + 12) * 2;
                    long insnsOff = codeOff + 16;
                    if (size <= 0 || insnsOff + size > buf.length) continue;
                    found.put(idx, new Method((int) codeOff, (int) insnsOff, (int) size));
                    Integer f = freq.get((int) codeOff);
                    freq.put((int) codeOff, f == null ? 1 : f + 1);
                }
            }
        }

        Map<Integer, Method> out = new LinkedHashMap<>();
        int skipped = 0;
        for (Map.Entry<Integer, Method> e : found.entrySet()) {
            if (freq.get(e.getValue().codeOff) > 1) { skipped++; continue; }
            out.put(e.getKey(), e.getValue());
        }
        return new MapResult(out, skipped);
    }
}
