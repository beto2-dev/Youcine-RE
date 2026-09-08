/*
 * Youcine-RE - phase 2: class warm-up sweep (rpc-driven, no auto-run).
 *
 * WHY: iJiami extracted ~45,238 method bodies at pack time (13,478
 * constructors + 31,760 void methods - every Companion.<init>, anonymous
 * listener, configView...) and re-materializes them in ART's in-memory
 * [anon:dalvik-DEX data] pages ONLY as classes load, from libexec's
 * encrypted blobs.  The phase-1 dump (run 34133100459) captured the
 * boot-path classes already restored and everything else still as
 * return-void+nop stubs - exactly why the v5 rebuild's dex2oat rejects
 * them ("Constructor returning without calling superclass constructor",
 * runs 34164727188 / 34166188171).  Force-loading every class from the
 * dumped DEXes here (Class.forName, initialize=true, loader cascade)
 * makes libexec fire the re-materialization AND the remaining
 * RegisterNatives calls, so the post-warm-up re-dump
 * (08_redump_dex.js + unpack/dexdata_extract.py) picks up complete
 * bodies.  The driver feeds batches of dot-notation names and collects
 * {ok, notfound, fail} evidence per batch.
 *
 * Robustness rule: a single bad class (VerifyError, missing superclass,
 * whatever Throwable the ART verifier invents) must NEVER abort the
 * sweep - every name is isolated in its own try/catch, and frida-level JS
 * exceptions are caught too (the sweep covers ~15k classes from 5 DEXes;
 * a large failure count is expected for stub-dependent classes).
 */
'use strict';

var PROGRESS_EVERY = 200; // send progress every N names (mirrors WARMUP_BATCH)
var MAX_ERRORS = 20;      // first N failure examples reported to the driver
var LOADERS = null;       // classloader cascade, cached once

function log(msg) {
  console.log('[warmup] ' + msg);
}

function errText(e) {
  try {
    if (e && typeof e.toString === 'function') {
      var s = e.toString();
      if (s) {
        return String(s);
      }
    }
  } catch (x) {}
  try {
    if (e && e.message) {
      return String(e.message);
    }
  } catch (x2) {}
  return 'unknown-error';
}

function classifyError(e) {
  // frida stringifies a Java Throwable as
  // 'java.lang.ClassNotFoundException: Didn't find class ...' (possibly
  // wrapped as 'Error: java.lang...' depending on runtime) - search the
  // whole text so both forms classify identically.
  var text = errText(e);
  if (text.indexOf('ClassNotFoundException') >= 0 ||
      text.indexOf('NoClassDefFoundError') >= 0) {
    return 'notfound';
  }
  // first dotted token = the Throwable class (for 'fail:<class>')
  var t = text.replace(/^Error:\s*/, '');
  var m = /^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z0-9_$]+)+/.exec(t);
  return 'fail:' + (m ? m[0] : 'unknown');
}

function getLoaders() {
  if (LOADERS) {
    return LOADERS;
  }
  var out = [];
  var seen = {};
  function add(h) {
    try {
      var key = String(h);
      if (seen[key]) {
        return;
      }
      seen[key] = true;
      out.push(h);
    } catch (e) {
      // keep going - a broken loader entry loses one candidate, not the sweep
    }
  }
  // raw jobject handles: the bridge wrapper's raw object pointer
  // (frida-java-bridge versions expose it as $handle OR $h - run
  // 34189152176 got 0 loaders with $handle only; the bridge's METHOD
  // MARSHALLING is broken under the stealth patch - $borrowClassHandle
  // TypeError - but wrapper creation and the raw JNIEnv are functional)
  function handleOf(w) {
    try {
      if (w) {
        if (w.$handle) { return w.$handle; }
        if (w.$h) { return w.$h; }
      }
    } catch (e) {}
    return null;
  }
  try {
    var main = Java.classFactory.loader;
    var h = handleOf(main);
    if (h) {
      add(ptr(h));
    } else {
      log('classFactory.loader handle not found ($handle/$h)');
    }
  } catch (e) {
    log('classFactory.loader: ' + e);
  }
  try {
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        var lh = handleOf(loader);
        if (lh) {
          add(ptr(lh));
        }
      },
      onComplete: function () {}
    });
  } catch (e) {
    log('enumerateClassLoaders: ' + e);
  }
  LOADERS = out;
  log('loader cascade: ' + out.length + ' classloader(s) (raw handles)');
  return out;
}

/* ------------------------------------------------------------------
 * raw-JNI warm-up: call Class.forName(String, boolean, ClassLoader)
 * DIRECTLY through the JNIEnv function table.  Vtable indices from the
 * authoritative jni.h struct order (+4 reserved slots, validated by the
 * two proven anchors RegisterNatives@215 and GetObjectRefType@232):
 * FindClass@6, GetMethodID@33, GetObjectClass@31, CallObjectMethod@34,
 * GetStaticMethodID@113, CallStaticObjectMethod@114, NewStringUTF@167,
 * GetStringUTFChars@169, ReleaseStringUTFChars@170, ExceptionCheck@228,
 * ExceptionClear@17, ExceptionOccurred@15, DeleteLocalRef@23.
 * ------------------------------------------------------------------ */
var JNI = null;

function jniInit(envHandle) {
  if (JNI && JNI.env.equals(envHandle)) {
    return JNI;
  }
  var E = envHandle;
  var table = Memory.readPointer(E);
  var ps = Process.pointerSize;
  function fn(slotIdx, ret, args) {
    return new NativeFunction(Memory.readPointer(table.add(slotIdx * ps)),
                              ret, args);
  }
  JNI = {
    env: E,
    FindClass: fn(6, 'pointer', ['pointer', 'pointer']),
    GetObjectClass: fn(31, 'pointer', ['pointer', 'pointer']),
    GetMethodID: fn(33, 'pointer',
                    ['pointer', 'pointer', 'pointer', 'pointer']),
    CallObjectMethod: fn(34, 'pointer',
                         ['pointer', 'pointer', 'pointer']),
    GetStaticMethodID: fn(113, 'pointer',
                          ['pointer', 'pointer', 'pointer', 'pointer']),
    CallStaticObjectMethod: fn(114, 'pointer',
                               ['pointer', 'pointer', 'pointer', 'pointer',
                                'int', 'pointer']),
    NewStringUTF: fn(167, 'pointer', ['pointer', 'pointer']),
    GetStringUTFChars: fn(169, 'pointer',
                          ['pointer', 'pointer', 'pointer']),
    ReleaseStringUTFChars: fn(170, 'void',
                              ['pointer', 'pointer', 'pointer']),
    ExceptionCheck: fn(228, 'int', ['pointer']),
    ExceptionClear: fn(17, 'void', ['pointer']),
    ExceptionOccurred: fn(15, 'pointer', ['pointer']),
    DeleteLocalRef: fn(23, 'void', ['pointer', 'pointer'])
  };
  return JNI;
}

function exceptionName(J, alloc) {
  try {
    var thr = J.ExceptionOccurred(J.env);
    if (thr.isNull()) {
      J.ExceptionClear(J.env);
      return '';
    }
    J.ExceptionClear(J.env);
    var tcls = J.GetObjectClass(J.env, thr);
    var mid = J.GetMethodID(J.env, tcls, alloc('getName'),
                            alloc('()Ljava/lang/String;'));
    var s = J.CallObjectMethod(J.env, thr, mid);
    var name = '';
    if (!s.isNull()) {
      var p = J.GetStringUTFChars(J.env, s, ptr(0));
      if (!p.isNull()) {
        name = Memory.readCString(p);
        J.ReleaseStringUTFChars(J.env, s, p);
      }
      J.DeleteLocalRef(J.env, s);
    }
    J.DeleteLocalRef(J.env, tcls);
    J.DeleteLocalRef(J.env, thr);
    return name;
  } catch (e) {
    try { J.ExceptionClear(J.env); } catch (ce) {}
    return '';
  }
}

function warmupInner(names) {
  var stats = { ok: 0, notfound: 0, fail: 0, errors: [] };
  var total = names.length;
  var J = null;
  var forNameMID = null;
  var clsClass = null;
  var loaders = [];
  try {
    var env = Java.vm.getEnv();
    J = jniInit(env.handle);
    var alloc = function (s) { return Memory.allocUtf8String(s); };
    clsClass = J.FindClass(J.env, alloc('java/lang/Class'));
    if (clsClass.isNull()) {
      throw new Error('FindClass(java/lang/Class) failed');
    }
    forNameMID = J.GetStaticMethodID(
        J.env, clsClass, alloc('forName'),
        alloc('(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;'));
    if (forNameMID.isNull()) {
      throw new Error('GetStaticMethodID(forName) failed');
    }
    loaders = getLoaders();
    J._alloc = alloc;
  } catch (e) {
    log('setup: ' + e);
    stats.errors.push('setup: ' + errText(e));
    return stats;
  }
  for (var idx = 0; idx < total; idx++) {
    var name = names[idx];
    if (typeof name !== 'string' || name.length === 0) {
      stats.fail++;
      continue;
    }
    var outcome = 'notfound';
    var reason = '';
    var js = J.NewStringUTF(J.env, J._alloc(name));
    for (var li = 0; li < loaders.length; li++) {
      var attempt = 'fail';
      // initialize=true: <clinit> must run so native libs load and
      // libexec's re-materialization gates actually fire
      var r = J.CallStaticObjectMethod(J.env, clsClass, forNameMID,
                                       js, 1, loaders[li]);
      if (J.ExceptionCheck(J.env) === 0) {
        attempt = 'ok';
        if (!r.isNull()) {
          J.DeleteLocalRef(J.env, r);
        }
      } else {
        var exName = exceptionName(J, J._alloc);
        reason = exName || 'exception';
        attempt = (exName.indexOf('ClassNotFoundException') >= 0 ||
                   exName.indexOf('NoClassDefFoundError') >= 0)
                  ? 'notfound' : 'fail';
      }
      if (attempt === 'ok') {
        outcome = 'ok';
        break;
      }
      if (attempt === 'notfound') {
        outcome = 'notfound';
        // another loader further down the cascade may define it
        continue;
      }
      outcome = attempt; // hard failure: remember it, still try next loader
    }
    J.DeleteLocalRef(J.env, js);
    if (outcome === 'ok') {
      stats.ok++;
    } else if (outcome === 'notfound') {
      stats.notfound++;
    } else {
      stats.fail++;
      if (stats.errors.length < MAX_ERRORS) {
        stats.errors.push(name + ': ' + (reason || outcome));
      }
    }
    if ((idx + 1) % PROGRESS_EVERY === 0 || idx + 1 === total) {
      try {
        send({
          type: 'warmup_progress',
          done: idx + 1,
          total: total,
          ok: stats.ok,
          notfound: stats.notfound,
          fail: stats.fail
        });
      } catch (se) {}
    }
  }
  return stats;
}

rpc.exports = {
  warmup: function (names) {
    var out = { ok: 0, notfound: 0, fail: 0, errors: [] };
    try {
      if (!names || typeof names.length !== 'number') {
        out.errors.push('warmup: names is not an array');
        return out;
      }
      Java.perform(function () {
        try {
          var r = warmupInner(names);
          out.ok = r.ok;
          out.notfound = r.notfound;
          out.fail = r.fail;
          out.errors = r.errors;
        } catch (e) {
          out.errors.push('warmupInner: ' + errText(e));
        }
      });
    } catch (e) {
      // frida-level failure (VM gone, thread detached, ...) - still JSON-able
      out.errors.push('warmup: ' + errText(e));
    }
    return out;
  },
  loadedcount: function () {
    // before/after evidence: how many classes ART has actually loaded
    var n = -1;
    try {
      Java.perform(function () {
        try {
          if (typeof Java.enumerateLoadedClassesSync === 'function') {
            n = Java.enumerateLoadedClassesSync().length;
          } else {
            n = 0;
            Java.enumerateLoadedClasses({
              onMatch: function (cn) {
                n++;
              },
              onComplete: function () {}
            });
          }
        } catch (e) {
          log('loadedcount: ' + e);
        }
      });
    } catch (e) {
      log('loadedcount: ' + e);
    }
    return n;
  }
};

/* ---------------------------------------------------------------------------
 * command bus (runs 34177514528/34181159206): the frida rpc PEER channel
 * is dead under the stealth patch - every script.exports call from the
 * driver times out while send()/post() script messages flow fine.  The
 * driver now posts {t:'cmd', cmd, id, args} and this dispatcher routes it
 * through the local rpc.exports table and replies {t:'reply', id, r}.
 * recv() is one-shot: re-arm after every message.
 * ------------------------------------------------------------------------- */
(function () {
  function listen() {
    recv(function (msg) {
      try {
        if (msg && msg.t === 'cmd' && msg.id !== undefined) {
          var fn = rpc.exports && rpc.exports[msg.cmd];
          var r;
          try {
            r = (typeof fn === 'function') ?
                fn.apply(null, msg.args || []) :
                { __err: 'no such cmd: ' + msg.cmd };
          } catch (e) {
            r = { __err: String(e) };
          }
          send({ t: 'reply', id: msg.id, r: r });
        }
      } catch (e) { /* never crash the script */ }
      listen();
    });
  }
  listen();
})();
