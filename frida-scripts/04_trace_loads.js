// Youcine-RE - iJiami load tracer.
// Spawn-gated into com.world.youcinemobile BEFORE any app code runs.
// Answers: which System.load/System.loadLibrary fails and WHY (the
// UnsatisfiedLinkError carries the linker/dlerror string), plus native
// android_dlopen_ext results for libexec/ijm libraries, ptrace usage and
// self-kill attempts (anti-debug / anti-tamper).

function log(msg) {
    send({ t: 'log', msg: msg });
}

log('[*] tracer loaded');

// ---- Java layer: System.load / System.loadLibrary ------------------------
Java.perform(function () {
    try {
        var Sys = Java.use('java.lang.System');
        Sys.load.overload('java.lang.String').implementation = function (path) {
            try {
                this.load(path);
                log('[+] System.load OK: ' + path);
            } catch (e) {
                log('[-] System.load FAIL: ' + path + ' :: ' + e);
            }
        };
        Sys.loadLibrary.overload('java.lang.String').implementation = function (name) {
            try {
                this.loadLibrary(name);
                log('[+] System.loadLibrary OK: ' + name);
            } catch (e) {
                log('[-] System.loadLibrary FAIL: ' + name + ' :: ' + e);
            }
        };
        log('[*] java hooks installed');
    } catch (e) {
        log('[-] java hook err: ' + e);
    }
});

// ---- Native layer: android_dlopen_ext / dlopen ----------------------------
function hookDlopen(name) {
    try {
        var addr = Module.getExportByName(null, name);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    this.path = args[0].readCString();
                } catch (e) {
                    this.path = null;
                }
            },
            onLeave: function (retval) {
                if (this.path === null) return;
                var p = this.path;
                if (
                    p.indexOf('libexec') >= 0 ||
                    p.indexOf('ijm') >= 0 ||
                    p.indexOf('stdc') >= 0 ||
                    p.indexOf('c++_shared') >= 0
                ) {
                    log('[dlopen ' + name + '] ' + p + ' -> ' + (retval.isNull() ? 'NULL' : 'ok'));
                }
            },
        });
        log('[*] hooked ' + name);
    } catch (e) {
        log('[-] hook ' + name + ' err: ' + e);
    }
}
hookDlopen('android_dlopen_ext');
hookDlopen('dlopen');

// ---- Anti-debug / self-kill watch -----------------------------------------
function watchExport(sym, fmt) {
    try {
        var addr = Module.getExportByName(null, sym);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                log(fmt(args));
            },
        });
        log('[*] watching ' + sym);
    } catch (e) {}
}
watchExport('ptrace', function (a) {
    return '[ptrace] req=' + a[0].toInt32() + ' pid=' + a[1].toInt32();
});
watchExport('kill', function (a) {
    return '[kill] pid=' + a[0].toInt32() + ' sig=' + a[1].toInt32();
});
watchExport('abort', function () {
    return '[abort] called';
});
watchExport('exit', function (a) {
    return '[exit] code=' + a[0].toInt32();
});

// ---- Periodic heartbeat -----------------------------------------------------
var beats = 0;
setInterval(function () {
    beats += 1;
    log('[hb] ' + beats * 5 + 's');
}, 5000);

log('[*] tracer ready');
