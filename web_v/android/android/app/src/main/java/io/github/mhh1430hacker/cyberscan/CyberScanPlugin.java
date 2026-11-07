package io.github.mhh1430hacker.cyberscan;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.WindowManager;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * CyberScan's own bridge to Android (window.CSNative in native.js):
 * hand-over of shared files and shortcut actions, the clipboard, secrets kept
 * with the Android Keystore, the fingerprint / screen-lock check, and hiding
 * the app from screenshots and the recent-apps preview.
 */
@CapacitorPlugin(name = "CyberScan")
public class CyberScanPlugin extends Plugin {
    private static final String KEY_ALIAS = "cyberscan-secrets";
    private static final String PREFS = "cyberscan-secrets";
    private static final int AUTHENTICATORS =
        BiometricManager.Authenticators.BIOMETRIC_WEAK | BiometricManager.Authenticators.DEVICE_CREDENTIAL;
    private static JSObject pending;
    private static CyberScanPlugin instance;

    @Override
    public void load() {
        instance = this;
    }

    /* ------------------------------------------------ shared files, shortcut actions */
    static synchronized void offer(JSObject item) {
        pending = item;
        if (instance != null) instance.notifyListeners("shared", new JSObject(), true);
    }

    @PluginMethod
    public void take(PluginCall call) {
        JSObject item;
        synchronized (CyberScanPlugin.class) {
            item = pending != null ? pending : new JSObject();
            pending = null;
        }
        call.resolve(item);
    }

    /* ------------------------------------------------ clipboard */
    @PluginMethod
    public void readClipboard(PluginCall call) {
        getActivity().runOnUiThread(() -> {
            JSObject out = new JSObject();
            try {
                ClipboardManager cm = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = cm != null ? cm.getPrimaryClip() : null;
                if (clip != null && clip.getItemCount() > 0) {
                    CharSequence text = clip.getItemAt(0).coerceToText(getContext());
                    out.put("text", text != null ? text.toString() : "");
                }
            } catch (Exception ignored) {
                // nothing readable on the clipboard
            }
            call.resolve(out);
        });
    }

    /* ------------------------------------------------ secrets (Android Keystore, AES-GCM) */
    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(KEY_ALIAS, null)).getSecretKey();
        }
        KeyGenerator gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        gen.init(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build());
        return gen.generateKey();
    }

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static String keyName(PluginCall call) {
        String k = call.getString("key", "");
        return k != null && k.matches("[a-z0-9_-]{1,40}") ? k : null;
    }

    @PluginMethod
    public void setSecret(PluginCall call) {
        String k = keyName(call);
        String value = call.getString("value", "");
        if (k == null || value == null) {
            call.reject("bad key name");
            return;
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key());
            byte[] sealed = c.doFinal(value.getBytes(StandardCharsets.UTF_8));
            String blob = Base64.encodeToString(c.getIV(), Base64.NO_WRAP) + ":" + Base64.encodeToString(sealed, Base64.NO_WRAP);
            prefs().edit().putString(k, blob).apply();
            call.resolve();
        } catch (Exception e) {
            call.reject("could not store the secret", e);
        }
    }

    @PluginMethod
    public void getSecret(PluginCall call) {
        String k = keyName(call);
        JSObject out = new JSObject();
        String blob = k != null ? prefs().getString(k, null) : null;
        if (blob == null) {
            out.put("value", "");
            call.resolve(out);
            return;
        }
        try {
            String[] parts = blob.split(":", 2);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)));
            out.put("value", new String(c.doFinal(Base64.decode(parts[1], Base64.NO_WRAP)), StandardCharsets.UTF_8));
        } catch (Exception e) {
            out.put("value", ""); // the key store was reset: the secret is gone
        }
        call.resolve(out);
    }

    @PluginMethod
    public void removeSecret(PluginCall call) {
        String k = keyName(call);
        if (k != null) prefs().edit().remove(k).apply();
        call.resolve();
    }

    /* ------------------------------------------------ app lock */
    @PluginMethod
    public void canAuthenticate(PluginCall call) {
        JSObject out = new JSObject();
        out.put("available", BiometricManager.from(getContext()).canAuthenticate(AUTHENTICATORS) == BiometricManager.BIOMETRIC_SUCCESS);
        call.resolve(out);
    }

    @PluginMethod
    public void authenticate(PluginCall call) {
        String title = call.getString("title", "CyberScan");
        String subtitle = call.getString("subtitle", "");
        getActivity().runOnUiThread(() -> {
            FragmentActivity activity = (FragmentActivity) getActivity();
            BiometricPrompt prompt = new BiometricPrompt(activity, ContextCompat.getMainExecutor(getContext()),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        JSObject out = new JSObject();
                        out.put("ok", true);
                        call.resolve(out);
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence message) {
                        JSObject out = new JSObject();
                        out.put("ok", false);
                        out.put("error", message != null ? message.toString() : "");
                        call.resolve(out);
                    }
                });
            BiometricPrompt.PromptInfo.Builder info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setAllowedAuthenticators(AUTHENTICATORS);
            if (subtitle != null && !subtitle.isEmpty()) info.setSubtitle(subtitle);
            try {
                prompt.authenticate(info.build());
            } catch (Exception e) {
                JSObject out = new JSObject();
                out.put("ok", false);
                out.put("error", e.getMessage());
                call.resolve(out);
            }
        });
    }

    /* ------------------------------------------------ screenshots / recent apps */
    @PluginMethod
    public void setSecure(PluginCall call) {
        boolean on = Boolean.TRUE.equals(call.getBoolean("on", false));
        getActivity().runOnUiThread(() -> {
            if (on) getActivity().getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            else getActivity().getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            if (Build.VERSION.SDK_INT >= 33) getActivity().setRecentsScreenshotEnabled(!on);
            call.resolve();
        });
    }

    /* ------------------------------------------------ about */
    @PluginMethod
    public void info(PluginCall call) {
        JSObject out = new JSObject();
        try {
            PackageInfo p = getContext().getPackageManager().getPackageInfo(getContext().getPackageName(), 0);
            out.put("version", p.versionName);
            out.put("build", Build.VERSION.SDK_INT >= 28 ? p.getLongVersionCode() : p.versionCode);
        } catch (Exception e) {
            out.put("version", "?");
        }
        out.put("android", Build.VERSION.RELEASE);
        out.put("sdk", Build.VERSION.SDK_INT);
        call.resolve(out);
    }
}
