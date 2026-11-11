package io.github.mhh1430hacker.cyberscan;

import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.OpenableColumns;

import com.getcapacitor.BridgeActivity;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * The CyberScan web app inside Android, plus what other apps hand over:
 * Share → CyberScan (one file, several files, a link or text), Open with →
 * CyberScan, and the launcher shortcuts / Quick Settings tile.
 */
public class MainActivity extends BridgeActivity {
    static final String ACTION_PICK = "io.github.mhh1430hacker.cyberscan.PICK";
    static final String ACTION_LINK = "io.github.mhh1430hacker.cyberscan.LINK";
    static final String ACTION_HISTORY = "io.github.mhh1430hacker.cyberscan.HISTORY";
    private static final long MAX_SHARED_BYTES = 100L * 1024 * 1024;
    private static final int MAX_SHARED_FILES = 50;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(CyberScanPlugin.class);
        super.onCreate(savedInstanceState);
        receive(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        receive(intent);
    }

    private void receive(Intent intent) {
        if (intent == null || intent.getAction() == null) return;
        String action = intent.getAction();
        switch (action) {
            case ACTION_PICK: offerAction("pick"); return;
            case ACTION_LINK: offerAction("link"); return;
            case ACTION_HISTORY: offerAction("history"); return;
            default: break;
        }
        List<Uri> uris = new ArrayList<>();
        if (Intent.ACTION_SEND.equals(action)) {
            Uri one = stream(intent);
            if (one != null) uris.add(one);
        } else if (Intent.ACTION_SEND_MULTIPLE.equals(action)) {
            ArrayList<Uri> many = Build.VERSION.SDK_INT >= 33
                ? intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri.class)
                : intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
            if (many != null) uris.addAll(many.subList(0, Math.min(many.size(), MAX_SHARED_FILES)));
        } else if (Intent.ACTION_VIEW.equals(action) && intent.getData() != null) {
            Uri data = intent.getData();
            String scheme = data.getScheme();
            if ("http".equals(scheme) || "https".equals(scheme)) {
                offerText(data.toString());
                return;
            }
            uris.add(data);
        }
        if (!uris.isEmpty()) {
            new Thread(() -> copyShared(uris)).start();
            return;
        }
        CharSequence text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
        if (text != null && text.length() > 0) offerText(text.toString());
    }

    @SuppressWarnings("deprecation")
    private static Uri stream(Intent intent) {
        return Build.VERSION.SDK_INT >= 33 ? intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class) : intent.getParcelableExtra(Intent.EXTRA_STREAM);
    }

    private static void offerAction(String action) {
        JSObject item = new JSObject();
        item.put("action", action);
        CyberScanPlugin.offer(item);
    }

    private static void offerText(String text) {
        JSObject item = new JSObject();
        item.put("text", text);
        CyberScanPlugin.offer(item);
    }

    /** Copy what was shared into the app's private cache, where the web app can read it. */
    private void copyShared(List<Uri> uris) {
        File dir = new File(getCacheDir(), "shared");
        File[] old = dir.listFiles();
        if (old != null) for (File f : old) f.delete();
        dir.mkdirs();
        JSArray files = new JSArray();
        int n = 0;
        for (Uri uri : uris) {
            File out = new File(dir, "incoming-" + (n++));
            if (copy(uri, out)) {
                JSObject f = new JSObject();
                f.put("path", out.getAbsolutePath());
                f.put("name", displayName(uri));
                files.put(f);
            }
        }
        if (files.length() == 0) return;
        JSObject item = new JSObject();
        item.put("files", files);
        CyberScanPlugin.offer(item);
    }

    private boolean copy(Uri uri, File out) {
        long total = 0;
        try (InputStream in = getContentResolver().openInputStream(uri); OutputStream os = new FileOutputStream(out)) {
            if (in == null) return false;
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > MAX_SHARED_BYTES) {
                    out.delete();
                    return false;
                }
                os.write(buf, 0, n);
            }
            return true;
        } catch (Exception e) {
            out.delete();
            return false;
        }
    }

    private String displayName(Uri uri) {
        try (Cursor c = getContentResolver().query(uri, new String[] { OpenableColumns.DISPLAY_NAME }, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String name = c.getString(0);
                if (name != null && !name.isEmpty()) return name;
            }
        } catch (Exception ignored) {
            // fall through to the last path segment
        }
        String last = uri.getLastPathSegment();
        return last != null ? last : "shared-file";
    }
}
