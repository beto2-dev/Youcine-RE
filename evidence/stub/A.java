package s.h.e.l.l;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ActivityThread;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.LoadedApk;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import java.io.File;
import java.lang.reflect.Field;

/* JADX INFO: loaded from: classes.dex */
@SuppressLint({"Override"})
@TargetApi(28)
public final class A extends AppComponentFactory {
    private String packageName = "com.world.youcinemobile";
    private String orignAppName = "com.mobile.brasiltv.app.App";
    private String orignName = "androidx.core.app.CoreComponentFactory";
    private AppComponentFactory orignACF = null;
    private boolean supportInstantiateClassLoader = false;
    private AppComponentFactory acf = null;

    public static native ClassLoader al(ClassLoader classLoader, ApplicationInfo applicationInfo, String str, String str2);

    private ApplicationInfo ga() throws Throwable {
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
            ActivityThread activityThreadCurrentActivityThread = ActivityThread.currentActivityThread();
            Field declaredField = activityThreadCurrentActivityThread.getClass().getDeclaredField("mBoundApplication");
            declaredField.setAccessible(true);
            Object obj5 = declaredField.get(activityThreadCurrentActivityThread);
            Field declaredField2 = obj5.getClass().getDeclaredField("info");
            declaredField2.setAccessible(true);
            return ((LoadedApk) declaredField2.get(obj5)).getApplicationInfo();
        } catch (Exception e9) {
            return null;
        }
    }

    private void ls(ApplicationInfo applicationInfo) throws Throwable {
        try {
            File file = new File(applicationInfo.dataDir, "files");
            if (!file.exists()) {
                file.mkdirs();
            }
            S.p = file.getAbsolutePath();
            S.f = applicationInfo.sourceDir;
            if (S.la) {
                S.l(null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public synchronized AppComponentFactory getACF(ClassLoader classLoader) {
        if (this.acf == null && this.orignName != null && !this.orignName.equals("")) {
            try {
                this.acf = (AppComponentFactory) classLoader.loadClass(this.orignName).newInstance();
            } catch (Exception e) {
            }
        }
        return this.acf;
    }

    @Override // android.app.AppComponentFactory
    public Activity instantiateActivity(ClassLoader classLoader, String str, Intent intent) throws IllegalAccessException, InstantiationException, ClassNotFoundException {
        if (S.l) {
            AppComponentFactory acf = getACF(classLoader);
            this.acf = acf;
            if (acf != null) {
                return this.acf.instantiateActivity(classLoader, str, intent);
            }
        }
        return super.instantiateActivity(classLoader, str, intent);
    }

    @Override // android.app.AppComponentFactory
    public Application instantiateApplication(ClassLoader classLoader, String str) throws Throwable {
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
        if (str.equals("s.h.e.l.l.S")) {
            if (!this.supportInstantiateClassLoader) {
                ApplicationInfo applicationInfoGa = ga();
                ls(applicationInfoGa);
                classLoader = N.al(classLoader, applicationInfoGa, this.packageName, this.orignAppName);
                applicationInfoGa.className = this.orignAppName;
            }
            str = this.orignAppName;
        } else if (S.l) {
            AppComponentFactory acf = getACF(classLoader);
            this.acf = acf;
            if (acf != null) {
                return this.acf.instantiateApplication(classLoader, str);
            }
        }
        return super.instantiateApplication(classLoader, str);
    }

    @Override // android.app.AppComponentFactory
    @TargetApi(29)
    public ClassLoader instantiateClassLoader(ClassLoader classLoader, ApplicationInfo applicationInfo) throws Throwable {
        Object obj;
        Object obj2;
        ClassLoader classLoaderAl;
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
            if (this.supportInstantiateClassLoader) {
                classLoaderAl = classLoader;
            } else {
                S.gST();
                ls(applicationInfo);
                classLoaderAl = N.al(classLoader, applicationInfo, this.packageName, this.orignAppName);
                try {
                    applicationInfo.className = this.orignAppName;
                    this.supportInstantiateClassLoader = true;
                    S.gET();
                } catch (Throwable th3) {
                }
            }
            if (S.l) {
                this.acf = getACF(classLoaderAl);
                if (this.acf != null) {
                    return this.acf.instantiateClassLoader(classLoaderAl, applicationInfo);
                }
            }
        } catch (Throwable th4) {
            classLoaderAl = classLoader;
        }
        return super.instantiateClassLoader(classLoaderAl, applicationInfo);
    }

    @Override // android.app.AppComponentFactory
    public ContentProvider instantiateProvider(ClassLoader classLoader, String str) throws IllegalAccessException, InstantiationException, ClassNotFoundException {
        if (S.l) {
            AppComponentFactory acf = getACF(classLoader);
            this.acf = acf;
            if (acf != null) {
                return this.acf.instantiateProvider(classLoader, str);
            }
        }
        return super.instantiateProvider(classLoader, str);
    }

    @Override // android.app.AppComponentFactory
    public BroadcastReceiver instantiateReceiver(ClassLoader classLoader, String str, Intent intent) throws IllegalAccessException, InstantiationException, ClassNotFoundException {
        if (S.l) {
            AppComponentFactory acf = getACF(classLoader);
            this.acf = acf;
            if (acf != null) {
                return this.acf.instantiateReceiver(classLoader, str, intent);
            }
        }
        return super.instantiateReceiver(classLoader, str, intent);
    }

    @Override // android.app.AppComponentFactory
    public Service instantiateService(ClassLoader classLoader, String str, Intent intent) throws IllegalAccessException, InstantiationException, ClassNotFoundException {
        if (S.l) {
            AppComponentFactory acf = getACF(classLoader);
            this.acf = acf;
            if (acf != null) {
                return this.acf.instantiateService(classLoader, str, intent);
            }
        }
        return super.instantiateService(classLoader, str, intent);
    }
}
