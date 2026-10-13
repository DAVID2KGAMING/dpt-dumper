package com.david2k.dptdumper.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/** Desktop test entry: java -cp <classes> com.david2k.dptdumper.core.CliMain <dex|apk> <Oooo> <out_dir> */
public final class CliMain {
    public static void main(String[] a) throws IOException {
        if (a.length != 3) { System.err.println("Usage: CliMain <dex|apk> <Oooo> <out_dir>"); System.exit(2); }
        final File out = new File(a[2]);
        File in = new File(a[0]);
        int rc = Restorer.run(Files.readAllBytes(in.toPath()), in.getName(), Files.readAllBytes(new File(a[1]).toPath()), true,
            new Restorer.Sink() {
                @Override public void write(String folder, String name, byte[] data) throws IOException {
                    File d = new File(out, folder); d.mkdirs();
                    Files.write(new File(d, name).toPath(), data);
                }
            },
            new Restorer.Log() {
                @Override public void log(String level, String msg) { System.out.println("[" + level + "] " + msg); }
            });
        System.exit(rc);
    }
}
