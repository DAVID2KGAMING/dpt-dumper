package com.david2k.dptdumper;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.david2k.dptdumper.core.Restorer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends Activity {
    private static final int REQ_DEX = 1, REQ_OOOO = 2, REQ_OUT = 3;
    private static final int BG = Color.parseColor("#0F1115"), CARD = Color.parseColor("#1A1D24"),
            ACCENT = Color.parseColor("#4F8CFF"), MUTED = Color.parseColor("#8A93A5");

    private final Handler ui = new Handler(Looper.getMainLooper());
    private Uri dexUri, ooooUri, outUri;
    private String dexName = "classes.dex";
    private TextView dexTv, ooooTv, outTv, logTv;
    private ScrollView scroll;
    private Button runBtn;
    private ProgressBar progress;
    private CheckBox extractedCb;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        buildUi();
    }

    // ---------------------------------------------------------------- UI
    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }

    private GradientDrawable round(int color, int radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(radiusDp));
        return g;
    }

    private TextView text(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private Button button(String label, boolean primary, View.OnClickListener l) {
        Button btn = new Button(this);
        btn.setText(label);
        btn.setAllCaps(false);
        btn.setTextColor(Color.WHITE);
        btn.setBackground(round(primary ? ACCENT : Color.parseColor("#2A2F3A"), 12));
        btn.setOnClickListener(l);
        return btn;
    }

    private void buildUi() {
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);

        scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(24), dp(16), dp(24));
        scroll.addView(root);

        root.addView(text("DPT Dumper", 26, Color.WHITE, true));
        TextView sub = text("Restore DEX files from DPT-Shell protected APKs", 13, MUTED, false);
        sub.setPadding(0, dp(2), 0, dp(16));
        root.addView(sub);

        dexTv = addPicker(root, "1. DEX or APK", "Select DEX / APK", new View.OnClickListener() {
            @Override public void onClick(View v) { pickFile(REQ_DEX); }
        });
        ooooTv = addPicker(root, "2. Oooo file", "Select Oooo", new View.OnClickListener() {
            @Override public void onClick(View v) { pickFile(REQ_OOOO); }
        });
        outTv = addPicker(root, "3. Output folder", "Select output folder", new View.OnClickListener() {
            @Override public void onClick(View v) {
                startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQ_OUT);
            }
        });

        extractedCb = new CheckBox(this);
        extractedCb.setText("Also save extracted DEX files");
        extractedCb.setTextColor(Color.WHITE);
        root.addView(extractedCb);

        runBtn = button("Restore DEX", true, new View.OnClickListener() {
            @Override public void onClick(View v) { startRun(); }
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(52));
        lp.topMargin = dp(12);
        root.addView(runBtn, lp);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        progress.setVisibility(View.GONE);
        root.addView(progress);

        logTv = text("", 12, Color.parseColor("#C9D1E0"), false);
        logTv.setTypeface(Typeface.MONOSPACE);
        logTv.setTextIsSelectable(true);
        logTv.setPadding(dp(12), dp(12), dp(12), dp(12));
        logTv.setBackground(round(CARD, 12));
        LinearLayout.LayoutParams ll = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        ll.topMargin = dp(16);
        root.addView(logTv, ll);

        setContentView(scroll);
    }

    private TextView addPicker(LinearLayout root, String title, String btnLabel, View.OnClickListener l) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(12), dp(14), dp(12));
        card.setBackground(round(CARD, 14));
        card.addView(text(title, 14, Color.WHITE, true));
        TextView value = text("Not selected", 12, MUTED, false);
        value.setPadding(0, dp(2), 0, dp(8));
        card.addView(value);
        card.addView(button(btnLabel, false, l), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(46)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        root.addView(card, lp);
        return value;
    }

    // ------------------------------------------------------------ picking
    private void pickFile(int req) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, req);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (res != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (req == REQ_DEX) {
            dexUri = uri;
            dexName = displayName(uri);
            dexTv.setText(dexName);
        } else if (req == REQ_OOOO) {
            ooooUri = uri;
            ooooTv.setText(displayName(uri));
        } else if (req == REQ_OUT) {
            outUri = uri;
            try {
                getContentResolver().takePersistableUriPermission(uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            } catch (Exception ignored) { }
            outTv.setText(Uri.decode(uri.getLastPathSegment() == null ? uri.toString() : uri.getLastPathSegment()));
        }
    }

    private String displayName(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (i >= 0 && c.getString(i) != null) return c.getString(i);
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) c.close();
        }
        String p = uri.getLastPathSegment();
        return p == null ? "file" : p.substring(p.lastIndexOf('/') + 1);
    }

    // ---------------------------------------------------------------- run
    private void log(final String level, final String msg) {
        final String prefix;
        switch (level) {
            case "success": prefix = "[+] "; break;
            case "error": prefix = "[!] "; break;
            case "debug": prefix = "[DEBUG] "; break;
            default: prefix = "[*] ";
        }
        ui.post(new Runnable() {
            @Override public void run() {
                logTv.append(prefix + msg + "\n");
                scroll.post(new Runnable() { @Override public void run() { scroll.fullScroll(View.FOCUS_DOWN); } });
            }
        });
    }

    private void startRun() {
        if (dexUri == null || ooooUri == null) {
            Toast.makeText(this, "Select the DEX/APK and the Oooo file first", Toast.LENGTH_SHORT).show();
            return;
        }
        logTv.setText("");
        runBtn.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        final boolean saveExtracted = extractedCb.isChecked();
        final Uri dex = dexUri, oooo = ooooUri, out = outUri;
        final String name = dexName;

        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    byte[] dexBytes = readAll(dex);
                    byte[] ooooBytes = readAll(oooo);
                    String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
                    Restorer.Sink sink = out != null ? new TreeSink(out, "DPT_Dumper_" + stamp)
                            : new FileSink(new File(getExternalFilesDir(null), "DPT_Dumper_" + stamp));
                    Restorer.Log logger = new Restorer.Log() {
                        @Override public void log(String level, String msg) { MainActivity.this.log(level, msg); }
                    };
                    if (out == null) log("info", "No output folder selected; saving to app storage.");
                    Restorer.run(dexBytes, name, ooooBytes, saveExtracted, sink, logger);
                    if (out != null) log("info", "Saved in: DPT_Dumper_" + stamp + "/restored");
                } catch (Throwable t) {
                    log("error", t.getClass().getSimpleName() + ": " + t.getMessage());
                } finally {
                    ui.post(new Runnable() {
                        @Override public void run() {
                            runBtn.setEnabled(true);
                            progress.setVisibility(View.GONE);
                        }
                    });
                }
            }
        }).start();
    }

    private byte[] readAll(Uri uri) throws IOException {
        InputStream in = getContentResolver().openInputStream(uri);
        if (in == null) throw new IOException("Cannot open " + uri);
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toByteArray();
        } finally {
            in.close();
        }
    }

    // ------------------------------------------------------------- sinks
    /** Writes into a folder chosen with the system folder picker (SAF). */
    private final class TreeSink implements Restorer.Sink {
        private final ContentResolver cr = getContentResolver();
        private final Uri runDir;
        private final Map<String, Uri> folders = new HashMap<>();

        TreeSink(Uri tree, String runName) throws IOException {
            Uri parent = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree));
            runDir = create(parent, DocumentsContract.Document.MIME_TYPE_DIR, runName);
        }

        private Uri create(Uri parent, String mime, String name) throws IOException {
            try {
                Uri u = DocumentsContract.createDocument(cr, parent, mime, name);
                if (u == null) throw new IOException("Cannot create " + name);
                return u;
            } catch (Exception e) {
                throw new IOException("Cannot create " + name + ": " + e.getMessage());
            }
        }

        @Override
        public void write(String folder, String name, byte[] data) throws IOException {
            Uri dir = folders.get(folder);
            if (dir == null) {
                dir = create(runDir, DocumentsContract.Document.MIME_TYPE_DIR, folder);
                folders.put(folder, dir);
            }
            Uri file = create(dir, "application/octet-stream", name);
            OutputStream os = cr.openOutputStream(file);
            if (os == null) throw new IOException("Cannot write " + name);
            try { os.write(data); } finally { os.close(); }
        }
    }

    /** Fallback: app-specific external storage. */
    private static final class FileSink implements Restorer.Sink {
        private final File root;
        FileSink(File root) { this.root = root; }

        @Override
        public void write(String folder, String name, byte[] data) throws IOException {
            File dir = new File(root, folder);
            if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("Cannot create " + dir);
            FileOutputStream os = new FileOutputStream(new File(dir, name));
            try { os.write(data); } finally { os.close(); }
        }
    }
}
