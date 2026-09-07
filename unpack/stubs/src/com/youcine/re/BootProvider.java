package com.youcine.re;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

import java.lang.reflect.Method;

/**
 * Early DE-SDK loader for the packer-stripped research build.
 *
 * Why this exists: iJiami's method-level SO protection converted ~800 Java
 * methods (com.arialyy.aria.orm.SqlHelper.getDb, the whole EFS prefs SDK,
 * 400+ com.mobile.brasiltv.* methods...) into ACC_NATIVE stubs whose bodies
 * live in assets/libijmDataEncryption_<abi>.so. In the PACKED app the
 * packer's native loader called com.ijm.dataencryption.DETool.loadDEso()
 * (the stub S.sp() reflects a loadDEso(String,String,String) overload that
 * does not even exist in this DE SDK version - the real entry is
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
 * this very app. loadDEso then: picks the asset for the runtime ABI
 * (/proc/self/exe e_machine + /proc/self/maps lib64 probing), copies it to
 * files/libijmDataEncryption.so, System.load()s it and calls
 * dowork("qmFJh65QoklKoT9Vs7hFrSU=;<pkg>", 1024, "9EC8AE...", ...).
 *
 * Everything is reflection + defensive try/catch: this class must NEVER
 * break the boot of the research build, only enable it.
 */
public final class BootProvider extends ContentProvider {

    private static final String TAG = "YoucineRE";
    private static final String DE_CLASS = "com.ijm.dataencryption.DETool";

    @Override
    public boolean onCreate() {
        Log.i(TAG, "BootProvider onCreate: loading iJiami DE SDK");
        try {
            Class<?> clz = Class.forName(DE_CLASS);
            Method m = clz.getDeclaredMethod("loadDEso", android.content.Context.class);
            m.setAccessible(true);
            Object result = m.invoke(null, getContext());
            Log.i(TAG, "DETool.loadDEso invoked, result=" + result);
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
                    m.invoke(
                        null,
                        getContext().getPackageCodePath(),
                        getContext().getFilesDir().getAbsolutePath(),
                        getContext().getPackageName());
                    Log.i(TAG, "DETool.loadDEso(String,String,String) invoked");
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "DETool.loadDEso(3-arg) failed", t);
        }
        return true;
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
