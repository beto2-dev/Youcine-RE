package com.youcine.re;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Early DE-SDK loader for the packer-stripped research build.
 *
 * Why this exists: iJiami's method-level SO protection converted ~800 Java
 * methods (com.arialyy.aria.orm.SqlHelper.getDb, the whole EFS prefs SDK,
 * 400+ com.mobile.brasiltv.* methods...) into ACC_NATIVE stubs and replaced
 * a second family of bodies (inner-class/Companion constructors - e.g.
 * com.facebook.appevents.AppEvent$SerializationProxyV2$Companion.<init>,
 * tv.danmaku.ijk...ExoMediaPlayer$1.<init>) with return-void+nop extraction
 * stubs. The native bodies/restorations live in
 * assets/libijmDataEncryption_<abi>.so (the ijm DE SDK). In the PACKED app
 * the packer's native loader invoked com.ijm.dataencryption.DETool.loadDEso
 * (the stub S.sp() reflects a loadDEso(String,String,String) overload that
 * does not even exist in DE SDK 4.3.4 - the real entry is
 * loadDEso(Context)) before handing control to the real Application, so
 * the JNI registrations were in place by App.onCreate -> Aria.init.
 *
 * In the packer-free rebuild nobody loads the DE library: the crash chain
 * is App.onCreate:139 -> Aria.init -> AriaManager.initDb -> SqlHelper.getDb
 * -> UnsatisfiedLinkError (boot-test run 34142729238).
 *
 * Content providers are installed by ActivityThread.installContentProviders
 * BEFORE Application.onCreate, so a provider is the earliest hook point
 * that still has a fully functional Context (getFilesDir/getAssets) - the
 * same early-init pattern FacebookInitProvider/Firebase already use in
 * this very app.
 *
 * ABI correctness (run 34164727188): DETool.loadDEso picks the asset by
 * reading /proc/self/exe's e_machine. On an x86_64 emulator running the
 * app under ndk_translation that probe returns the HOST arch (x86_64) but
 * the translated dlopen namespace only accepts the app's primaryCpuAbi
 * (arm64-v8a): dlopen fails with "is for EM_X86_64 (62) instead of
 * EM_AARCH64 (183)". This provider therefore compares DETool's probe
 * result with the PackageManager-chosen primaryCpuAbi and, when they
 * disagree, performs its own copy + System.load + dowork(...) with the
 * exact arguments loadDEso would have used.
 *
 * Everything is reflection + defensive try/catch: this class must NEVER
 * break the boot of the research build, only enable it.
 */
public final class BootProvider extends ContentProvider {

    private static final String TAG = "YoucineRE";
    private static final String DE_CLASS = "com.ijm.dataencryption.DETool";
    private static final String DE_LIB_FILE = "libijmDataEncryption.so";

    @Override
    public boolean onCreate() {
        Context ctx = getContext();
        Log.i(TAG, "BootProvider onCreate: loading iJiami DE SDK");
        // 1) Best effort: the original path. Correct on real devices of
        //    every ABI (also sets DETool.mContext / attachCount).
        invokeLoadDEso(ctx);
        // 2) Translated-runtime rescue: DETool's /proc/self/exe probe picks
        //    the host arch; under ndk_translation the linker namespace only
        //    accepts primaryCpuAbi. Do our own load when they disagree.
        try {
            String correct = assetForPrimaryAbi(ctx);
            String probed = assetForProcExe();
            Log.i(TAG, "DE asset: primaryCpuAbi=" + correct
                    + " probe=" + probed);
            if (correct != null && !correct.equals(probed)) {
                ownLoad(ctx, correct);
            }
        } catch (Throwable t) {
            Log.w(TAG, "DE rescue path failed", t);
        }
        return true;
    }

    private void invokeLoadDEso(Context ctx) {
        try {
            Class<?> clz = Class.forName(DE_CLASS);
            Method m = clz.getDeclaredMethod("loadDEso", Context.class);
            m.setAccessible(true);
            m.invoke(null, ctx);
            Log.i(TAG, "DETool.loadDEso invoked");
        } catch (Throwable t) {
            Log.w(TAG, "DETool.loadDEso failed", t);
        }
        // Also try the (String,String,String) overload the stub S.sp()
        // reflects - belt and suspenders across DE SDK versions.
        try {
            Class<?> clz = Class.forName(DE_CLASS);
            for (Method m : clz.getDeclaredMethods()) {
                if (!m.getName().equals("loadDEso")) {
                    continue;
                }
                Class<?>[] p = m.getParameterTypes();
                if (p.length == 3 && p[0] == String.class && p[1] == String.class
                        && p[2] == String.class) {
                    m.setAccessible(true);
                    m.invoke(null, ctx.getPackageCodePath(),
                            ctx.getFilesDir().getAbsolutePath(),
                            ctx.getPackageName());
                    Log.i(TAG, "DETool.loadDEso(String,String,String) invoked");
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "DETool.loadDEso(3-arg) failed", t);
        }
    }

    /** Asset variant the PackageManager-chosen ABI requires (what the
     * app's dlopen namespace will accept), or null when unknown.
     * primaryCpuAbi is @UnsupportedAppUsage (greylist) so we try it via
     * reflection first and fall back to the public nativeLibraryDir
     * (its last path segment encodes the ABI: arm64 / arm / x86_64 / x86). */
    private String assetForPrimaryAbi(Context ctx) {
        try {
            ApplicationInfo ai = ctx.getApplicationInfo();
            String source = null;
            try {
                Field f = ApplicationInfo.class.getField("primaryCpuAbi");
                Object v = f.get(ai);
                if (v instanceof String && !((String) v).isEmpty()) {
                    source = (String) v;
                }
            } catch (Throwable ignored) {
            }
            if (source == null) {
                source = ai.nativeLibraryDir;
            }
            Log.i(TAG, "abi source: " + source);
            if (source == null || source.isEmpty()) {
                return null;
            }
            String last = new File(source).getName();
            if (source.contains("arm64-v8a") || last.equals("arm64")) {
                return "libijmDataEncryption_arm64.so";
            }
            if (source.contains("armeabi") || last.equals("arm")) {
                return "libijmDataEncryption.so"; // 32-bit arm default asset
            }
            if (source.contains("x86_64") || last.equals("x86_64")) {
                return "libijmDataEncryption_x86_64.so";
            }
            if (source.contains("x86") || last.equals("x86")) {
                return "libijmDataEncryption_x86.so";
            }
        } catch (Throwable t) {
            Log.w(TAG, "primaryCpuAbi probe failed", t);
        }
        return null;
    }

    /** Mirrors DETool's own probe (getRuntimeAbi + is64BitMode) so we can
     * detect the disagreement. */
    private String assetForProcExe() {
        try {
            int em = readElfMachine("/proc/self/exe");
            boolean b64 = is64BitRuntime();
            boolean x86Family = (em == 3 || em == 6 || em == 7 || em == 62);
            if (x86Family) {
                return b64 ? "libijmDataEncryption_x86_64.so"
                        : "libijmDataEncryption_x86.so";
            }
            return b64 ? "libijmDataEncryption_arm64.so"
                    : "libijmDataEncryption.so";
        } catch (Throwable t) {
            return null;
        }
    }

    private void ownLoad(Context ctx, String assetName) throws Exception {
        File out = new File(ctx.getFilesDir(), DE_LIB_FILE);
        copyAsset(ctx, assetName, out);
        Log.i(TAG, "copied " + assetName + " -> " + out
                + " (" + out.length() + " bytes)");
        // keep DETool.mContext consistent with what loadDEso would set
        try {
            Class<?> clz = Class.forName(DE_CLASS);
            Field f = clz.getDeclaredField("mContext");
            f.setAccessible(true);
            f.set(null, ctx);
        } catch (Throwable t) {
            Log.w(TAG, "DETool.mContext set failed", t);
        }
        System.load(out.getAbsolutePath());
        Log.i(TAG, "System.load(" + out + ") OK");
        // dowork(...) with the exact arguments DETool.loadDEso passes
        Class<?> clz = Class.forName(DE_CLASS);
        Method dw = clz.getDeclaredMethod("dowork",
                String.class, int.class, String.class, String.class,
                String.class, boolean.class);
        dw.setAccessible(true);
        Object r = dw.invoke(null,
                "qmFJh65QoklKoT9Vs7hFrSU=;" + ctx.getPackageName(),
                1024,
                "9EC8AE47604E3A04BA7BBBB56C216F28EEC1E22C99FCB92BCBF0495D974DB103",
                "0x4096",
                "0x16384",
                Boolean.FALSE);
        Log.i(TAG, "DETool.dowork -> " + r);
    }

    private void copyAsset(Context ctx, String name, File out) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        try {
            OutputStream os = new FileOutputStream(out);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
                os.flush();
            } finally {
                close(os);
            }
        } finally {
            close(in);
        }
    }

    private static void close(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /** e_machine of an ELF file (bytes 18..19, little endian). */
    private int readElfMachine(String path) {
        try {
            InputStream in = new java.io.FileInputStream(path);
            try {
                byte[] h = new byte[20];
                int off = 0;
                while (off < 20) {
                    int n = in.read(h, off, 20 - off);
                    if (n <= 0) {
                        return -1;
                    }
                    off += n;
                }
                return (h[18] & 0xFF) | ((h[19] & 0xFF) << 8);
            } finally {
                close(in);
            }
        } catch (Throwable t) {
            return -1;
        }
    }

    /** Mirrors DETool.is64BitMode: /proc/self/maps mentions lib64. */
    private boolean is64BitRuntime() {
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(
                            new java.io.FileInputStream("/proc/self/maps")));
            try {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.contains("/system/lib64/libart.so")
                            || line.contains("/system/lib64/libartpalette-system")
                            || line.contains("/system/lib64/libaoc.so")
                            || line.contains("/system/bin/linker64")) {
                        return true;
                    }
                }
            } finally {
                close(br);
            }
        } catch (Throwable t) {
            Log.w(TAG, "maps probe failed", t);
        }
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        return 0;
    }
}
