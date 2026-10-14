package com.david2k.dptdumper.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Restores DEX files using the saved method bodies from the Oooo file. */
public final class Restorer {
    public interface Log { void log(String level, String msg); }          // info | success | error | debug
    public interface Sink { void write(String folder, String name, byte[] data) throws IOException; }

    private static final class NamedDex {
        final String name; final byte[] data;
        NamedDex(String n, byte[] d) { name = n; data = d; }
    }

    private Restorer() {}

    private static List<NamedDex> collectDexes(byte[] input, String inputName) throws IOException {
        List<NamedDex> out = new ArrayList<>();
        if (DexUtil.isDex(input)) {
            out.add(new NamedDex(inputName, input));
            return out;
        }
        int start = -1;
        for (int i = 0; i + 4 <= input.length; i++) {
            if (input[i] == 'P' && input[i + 1] == 'K' && input[i + 2] == 3 && input[i + 3] == 4) { start = i; break; }
        }
        if (start < 0) return out;

        Set<String> used = new HashSet<>();
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(input, start, input.length - start))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (e.isDirectory() || !e.getName().endsWith(".dex")) continue;
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                byte[] tmp = new byte[65536];
                int n;
                while ((n = z.read(tmp)) > 0) bo.write(tmp, 0, n);
                String name = e.getName();
                String base = name.substring(name.lastIndexOf('/') + 1);
                if (!used.add(base)) { base = name.replace('/', '_'); used.add(base); }
                out.add(new NamedDex(base, bo.toByteArray()));
            }
        }
        Collections.sort(out, new Comparator<NamedDex>() {
            @Override public int compare(NamedDex a, NamedDex b) {
                int x = DexUtil.dexNumber(a.name), y = DexUtil.dexNumber(b.name);
                x = x >= 0 ? x : Integer.MAX_VALUE; y = y >= 0 ? y : Integer.MAX_VALUE;
                return x != y ? Integer.compare(x, y) : a.name.compareTo(b.name);
            }
        });
        return out;
    }

    /** Look inside an APK/zip for the Oooo file (assets/OoooooOooo). Returns null if not found. */
    public static byte[] findOooo(byte[] apk) throws IOException {
        int start = -1;
        for (int i = 0; i + 4 <= apk.length; i++) {
            if (apk[i] == 'P' && apk[i + 1] == 'K' && apk[i + 2] == 3 && apk[i + 3] == 4) { start = i; break; }
        }
        if (start < 0) return null;
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(apk, start, apk.length - start))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (e.isDirectory()) continue;
                String base = e.getName().substring(e.getName().lastIndexOf('/') + 1);
                if (!base.toLowerCase().startsWith("oooo")) continue;
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                byte[] tmp = new byte[65536];
                int n;
                while ((n = z.read(tmp)) > 0) bo.write(tmp, 0, n);
                return bo.toByteArray();
            }
        }
        return null;
    }

    /** Pick the Oooo block whose method sizes overlap the DEX the most. Returns {index, overlap}. */
    private static int[] bestBlock(Map<Integer, DexUtil.Method> dexMap, OoooParser oooo) {
        int bestI = -1, bestC = 0;
        for (Map.Entry<Integer, Map<Integer, byte[]>> b : oooo.blocks.entrySet()) {
            int c = 0;
            for (Map.Entry<Integer, DexUtil.Method> m : dexMap.entrySet()) {
                byte[] code = b.getValue().get(m.getKey());
                if (code != null && code.length == m.getValue().size) c++;
            }
            if (c > bestC) { bestC = c; bestI = b.getKey(); }
        }
        return new int[]{bestI, bestC};
    }

    /** @return 0 on success, 1 on failure */
    public static int run(byte[] input, String inputName, byte[] ooooData,
                          boolean saveExtracted, Sink sink, Log log) throws IOException {
        List<NamedDex> dexes = collectDexes(input, inputName);
        if (dexes.isEmpty()) { log.log("error", "No DEX files found in input."); return 1; }
        StringBuilder names = new StringBuilder();
        for (NamedDex d : dexes) names.append(names.length() == 0 ? "" : ", ").append(d.name);
        log.log("debug", "DEX files: " + names);

        if (ooooData.length > 3 && ooooData[0] == 'P' && ooooData[1] == 'K') {
            log.log("error", "The Oooo file you selected is an APK/zip, not an Oooo file. Leave Oooo empty to auto-detect it from the APK.");
            return 1;
        }
        OoooParser oooo = OoooParser.parse(ooooData);
        if (oooo.methodCount == 0) { log.log("error", "No methods parsed from Oooo file; nothing to patch."); return 1; }
        log.log("success", "Oooo dex_count=" + oooo.dexCount + ", methods=" + oooo.methodCount);

        int produced = 0;
        for (NamedDex nd : dexes) {
            log.log("info", "Processing " + nd.name);
            if (saveExtracted && !(dexes.size() == 1 && nd.data == input)) sink.write("extracted", nd.name, nd.data);

            byte[] out = nd.data.clone();
            DexUtil.MapResult mr;
            try {
                mr = DexUtil.mapMethods(nd.data);
            } catch (IOException e) {
                log.log("error", "DEX parse failed: " + nd.name + " (" + e.getMessage() + ")");
                DexUtil.fixHeader(out); sink.write("restored", nd.name, out); produced++;
                continue;
            }
            log.log("success", "Mapped=" + mr.methods.size() + " methods (skipped dup code_off=" + mr.skipped + ")");

            int[] best = bestBlock(mr.methods, oooo);
            if (best[0] < 0 || best[1] == 0) {
                log.log("error", "No suitable Oooo block matched (overlap=0). Output copy only.");
                DexUtil.fixHeader(out); sink.write("restored", nd.name, out); produced++;
                continue;
            }
            log.log("success", "Auto-aligned to Oooo dex_index=" + best[0] + " (overlap=" + best[1] + ")");

            Map<Integer, byte[]> block = oooo.blocks.get(best[0]);
            int applied = 0;
            for (Map.Entry<Integer, DexUtil.Method> m : mr.methods.entrySet()) {
                byte[] code = block.get(m.getKey());
                if (code == null || code.length != m.getValue().size) continue; // strict size equality
                System.arraycopy(code, 0, out, m.getValue().insnsOff, code.length);
                applied++;
            }
            DexUtil.fixHeader(out);
            sink.write("restored", nd.name, out);
            produced++;
            log.log("success", "Patched applied=" + applied + "/" + applied + " -> restored/" + nd.name);
        }
        log.log("success", "Done. Produced " + produced + " dex file(s).");
        return 0;
    }
}
