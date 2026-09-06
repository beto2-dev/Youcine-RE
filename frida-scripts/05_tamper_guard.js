// Youcine-RE - iJiami anti-tamper neutralizer + timed freezer.
//
// Injected (spawn-gated) into the dump-build (pure x86_64) process:
//  * suppresses libc kill/tgkill/exit/abort so the packer's signature
//    check cannot SIGKILL the process after it detects the re-signed APK
//  * traces System.load/loadLibrary failures (dlerror visibility)
//  * watches android_dlopen_ext for the libexec loads
//  * freezes the process with SIGSTOP at the PERFECT dump moment: when
//    Instrumentation.newApplication is about to instantiate the real
//    com.mobile.brasiltv.app.App - at that point N.al() has already
//    decrypted ijiami.dat and built the in-memory classloader, but the
//    real app has not yet crashed on its ARM-only native libs.

function log(msg) {
    send({ t: 'log', msg: msg });
}

log('[*] tamper guard loaded (pid ' + Process.id + ')');

// ---- suppressors -----------------------------------------------------------
function suppress(sym, ret, args) {
    try {
        var addr = Module.getExportByName('libc.so', sym);
        if (!addr) return;
        Interceptor.replace(addr, new NativeCallback(function () {
            var argv = [];
            for (var i = 0; i < args.length; i++) argv.push(arguments[i]);
            log('[guard] suppressed ' + sym + '(' + argv.join(', ') + ')');
            return ret;
        }, ret, args));
        log('[*] suppressing ' + sym);
    } catch (e) {
        log('[!] cannot suppress ' + sym + ': ' + e);
    }
}

suppress('kill', 'int', ['int', 'int']);
suppress('tgkill', 'int', ['int', 'int', 'int']);
suppress('abort', 'void', []);
suppress('exit', 'void', ['int']);
suppress('_exit', 'void', ['int']);
suppress('raise', 'int', ['int']);

// ---- traces ----------------------------------------------------------------
try {
    Interceptor.attach(Module.getExportByName('libc.so', 'ptrace'), {
        onEnter: function (args) {
            log('[ptrace] req=' + args[0].toInt32());
        },
    });
    log('[*] watching ptrace');
} catch (e) {}

['android_dlopen_ext', 'dlopen'].forEach(function (sym) {
    try {
        var addr = Module.getExportByName(null, sym);
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
                if (p.indexOf('libexec') >= 0 || p.indexOf('ijm') >= 0 || p.indexOf('stdc') >= 0) {
                    log('[dlopen] ' + p + ' -> ' + (retval.isNull() ? 'NULL' : 'ok'));
                }
            },
        });
    } catch (e) {}
});

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
    } catch (e) {
        log('[!] java hook err: ' + e);
    }

    // ---- THE FREEZE HOOK ---------------------------------------------------
    try {
        var Instrumentation = Java.use('android.app.Instrumentation');
        Instrumentation.newApplication.overload('java.lang.ClassLoader', 'java.lang.String').implementation =
            function (cl, name) {
                if (name && name.indexOf('brasiltv') >= 0) {
                    log('[FROZEN] real app about to instantiate: ' + name +
                        ' (decrypted DEX present in memory)');
                    // Direct syscall (bypasses our own libc kill suppressor):
                    // x86_64: syscall(62 /*kill*/, pid, 19 /*SIGSTOP*/)
                    var sysfn = new NativeFunction(
                        Module.getExportByName('libc.so', 'syscall'),
                        'int', ['int', 'int', 'int', 'int', 'int', 'int', 'int']
                    );
                    sysfn(62, Process.id, 19, 0, 0, 0, 0);
                }
                return this.newApplication(cl, name);
            };
        log('[*] freeze hook installed');
    } catch (e) {
        log('[!] freeze hook err: ' + e);
    }
});

log('[*] guard ready');
