package s.h.e.l.l;

import android.app.Application;
import android.content.pm.ApplicationInfo;
import java.io.File;
import java.io.FileInputStream;

/* JADX INFO: loaded from: classes.dex */
public final class N {
    static boolean la = true;

    static {
        Object obj;
        Object obj2;
        Object obj3 = null;
        try {
            obj2 = new Object();
            try {
                Object obj4 = new Object();
                if (obj2 != null) {
                    try {
                        obj2.hashCode();
                    } catch (Exception e) {
                    }
                }
                if (obj4 != null) {
                    try {
                        obj4.hashCode();
                    } catch (Exception e2) {
                    }
                }
            } catch (Exception e3) {
                if (obj2 != null) {
                    try {
                        obj2.hashCode();
                    } catch (Exception e4) {
                    }
                }
                if (0 != 0) {
                    try {
                        obj3.hashCode();
                    } catch (Exception e5) {
                    }
                }
            } catch (Throwable th) {
                obj = obj2;
                th = th;
                if (obj != null) {
                    try {
                        obj.hashCode();
                    } catch (Exception e6) {
                    }
                }
                if (0 == 0) {
                    throw th;
                }
                try {
                    obj3.hashCode();
                    throw th;
                } catch (Exception e7) {
                    throw th;
                }
            }
        } catch (Exception e8) {
            obj2 = null;
        } catch (Throwable th2) {
            th = th2;
            obj = null;
        }
        try {
            if (la) {
                System.load(String.valueOf(S.p) + "/libexec.so");
                if (S.m) {
                    System.load(String.valueOf(S.p) + "/libexecmain.so");
                    return;
                }
                return;
            }
            if (!x()) {
                System.loadLibrary("exec");
                if (S.m) {
                    System.loadLibrary("execmain");
                    return;
                }
                return;
            }
            try {
                System.loadLibrary("exec_x86");
                if (S.m) {
                    System.loadLibrary("execmain_x86");
                }
            } catch (Throwable th3) {
                System.loadLibrary("exec");
                if (S.m) {
                    System.loadLibrary("execmain");
                }
            }
        } catch (Throwable th4) {
        }
    }

    public static native ClassLoader al(ClassLoader classLoader, ApplicationInfo applicationInfo, String str, String str2);

    public static native byte[] b2b(byte[] bArr, int i);

    public static native boolean l(Application application, String str);

    public static native void m(String str, int i);

    public static native boolean r(Application application, String str);

    public static native boolean ra(Application application, String str);

    public static native void sa(String str, String str2);

    public static boolean x() throws Throwable {
        Object obj;
        Object obj2;
        Object obj3 = null;
        try {
            obj2 = new Object();
            try {
                Object obj4 = new Object();
                if (obj2 != null) {
                    try {
                        obj2.hashCode();
                    } catch (Exception e) {
                    }
                }
                if (obj4 != null) {
                    try {
                        obj4.hashCode();
                    } catch (Exception e2) {
                    }
                }
            } catch (Exception e3) {
                if (obj2 != null) {
                    try {
                        obj2.hashCode();
                    } catch (Exception e4) {
                    }
                }
                if (0 != 0) {
                    try {
                        obj3.hashCode();
                    } catch (Exception e5) {
                    }
                }
            } catch (Throwable th) {
                obj = obj2;
                th = th;
                if (obj != null) {
                    try {
                        obj.hashCode();
                    } catch (Exception e6) {
                    }
                }
                if (0 == 0) {
                    throw th;
                }
                try {
                    obj3.hashCode();
                    throw th;
                } catch (Exception e7) {
                    throw th;
                }
            }
        } catch (Exception e8) {
            obj2 = null;
        } catch (Throwable th2) {
            th = th2;
            obj = null;
        }
        try {
            String strA = S.a();
            try {
                byte[] bArr = new byte[20];
                File file = new File("/system/bin/linker");
                if (!file.exists()) {
                    file = new File("/system/bin/linker64");
                }
                FileInputStream fileInputStream = new FileInputStream(file);
                if (fileInputStream != null) {
                    fileInputStream.read(bArr);
                    fileInputStream.close();
                    switch (bArr[18]) {
                        case -73:
                            strA = "arm64-v8a";
                            break;
                        case 3:
                            strA = "x86";
                            break;
                        case 40:
                            strA = "armeabi";
                            break;
                        case 62:
                            strA = "x86_64";
                            break;
                    }
                }
            } catch (Exception e9) {
            }
            return strA != null && strA.contains("x86");
        } catch (Exception e10) {
        }
    }
}
