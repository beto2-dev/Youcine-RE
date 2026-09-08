/*
 * Youcine-RE - phase 2: capture the RegisterNatives table, OBSERVE-ONLY.
 * Run against the ORIGINAL packed APK (the content-gated engine only
 * registers on the byte-exact original - run 34133100459 is the proven
 * environment: native-arm64 redroid + original APK).
 *
 * WHY: the ~805 ACC_NATIVE methods (17 com.arialyy.*, 424
 * com.mobile.brasiltv.*, 53 com.facebook.*, EFS, ...) receive their JNI
 * implementations ONLY at runtime from libexec.so's content-gated engine.
 * The packer-free rebuild v5 executes every non-protected layer and then
 * dies at the first VMP-protected method (App.onCreate:139 -> Aria.init ->
 * SqlHelper.getDb, runs 34166188171/34166250339): removing the packer
 * removed the only registrar.  This script records
 * class -> {name, signature, fnPtr(module+offset)} for every registered
 * native, so the later de-natify bridge can map each native back to its
 * Java-visible declaration.
 *
 * HOW (matrix runs 34175381036 / 34175793717 verdict): EVERY active
 * interception of RegisterNatives is detected by iJiami's VMP -
 *   * Interceptor.attach on the art::JNI::RegisterNatives body (inline
 *     code patch on libart) -> process killed,
 *   * swapping JNINativeInterface slot 215 (a pure DATA patch) -> the
 *     packer refuses to run Application attach and the process dies on a
 *     provider-install NPE.
 * BUT the app fully boots with the agent injected (matrix L1: alive) -
 * the registrations DO happen, we only need to OBSERVE them afterwards.
 * So this script modifies NOTHING: after the app boots (driver triggers
 * the sweep post-warm-up), Java reflection enumerates the loaded
 * classes, records every native-declared method, and reads the JNI
 * entry point best-effort:
 *   layer 1: the Method object's hidden artMethod field (offset found
 *            empirically from a known framework native - a pointer slot
 *            whose target looks like an ArtMethod),
 *   layer 2: the ArtMethod's entry-point slot (offset found the same
 *            way: a pointer landing inside a known executable module).
 * Reads are never detectable; offsets are validated on two known
 * framework natives before use and silently disabled on mismatch.
 *
 * Style follows 01_unpack_ijiami_dex.js: /proc/self/cmdline target gating,
 * 'use strict', and total try/catch discipline.
 */
'use strict';

var TARGET = 'com.world.youcinemobile';
var activated = false;
var swept = false;

// className -> { 'name|sig' -> rec }
var RN = {};

// empirically discovered offsets (0 = not found yet / -1 = unavailable)
var OFF_ARTMETHOD = 0;   // Method object -> artMethod pointer slot
var OFF_ENTRY = 0;       // ArtMethod -> entry_point_from_jni_ slot

var PRIM = {
  void: 'V', boolean: 'Z', byte: 'B', char: 'C', short: 'S',
  int: 'I', long: 'J', float: 'F', double: 'D'
};

function log(msg) {
  console.log('[rn] ' + msg);
}

function cmdline() {
  try {
    var f = new File('/proc/self/cmdline', 'r');
    var s = f.readLine();
    f.close();
    return (s || '').replace(/\u0000/g, '');
  } catch (e) {
    return '';
  }
}

function isTarget() {
  var c = cmdline();
  return c === TARGET || c.indexOf(TARGET) === 0;
}

function record(className, rec) {
  var bucket = RN[className];
  if (!bucket) {
    bucket = {};
    RN[className] = bucket;
  }
  bucket[rec.name + '|' + rec.sig] = rec;
}

function totalMethods() {
  var n = 0;
  for (var cls in RN) {
    if (Object.prototype.hasOwnProperty.call(RN, cls)) {
      for (var k in RN[cls]) {
        if (Object.prototype.hasOwnProperty.call(RN[cls], k)) n++;
      }
    }
  }
  return n;
}

function typeSig(name) {
  if (PRIM[name]) {
    return PRIM[name];
  }
  if (name.charAt(0) === '[') {
    return name.replace(/\./g, '/');       // already array-ish
  }
  return 'L' + name.replace(/\./g, '/') + ';';
}

function sigOf(m) {
  try {
    var pt = m.getParameterTypes();
    var s = '(';
    for (var i = 0; i < pt.length; i++) {
      s += typeSig(String(pt[i].getName()));
    }
    s += ')';
    s += typeSig(String(m.getReturnType().getName()));
    return s;
  } catch (e) {
    return '?';
  }
}

/* pointer at obj+offset that lands in an executable module (or null) */
function ptrInModuleAt(obj, off) {
  try {
    var p = Memory.readPointer(obj.add(off));
    if (p.isNull()) {
      return null;
    }
    var mod = Process.findModuleByAddress(p);
    if (mod) {
      return p;
    }
  } catch (e) {}
  return null;
}

/* Discover OFF_ARTMETHOD and OFF_ENTRY from known framework natives.
 * android.util.Log has native methods registered by
 * libandroid_runtime.so at boot - their entry points live there. */
function discoverOffsets() {
  try {
    var Log = Java.use('android.util.Log').class;
    var methods = Log.getDeclaredMethods();
    var samples = [];
    for (var i = 0; i < methods.length && samples.length < 2; i++) {
      var m = methods[i];
      if ((m.getModifiers() & 0x100) !== 0) {   // Modifier.NATIVE
        samples.push(m);
      }
    }
    if (samples.length === 0) {
      log('offset discovery: no framework native sample - fn reads off');
      OFF_ARTMETHOD = -1;
      OFF_ENTRY = -1;
      return;
    }
    // layer 1: scan the Method object for a plausible ArtMethod pointer:
    // an aligned slot whose target (small struct) itself contains a
    // pointer into an executable module within the first 0x30 bytes.
    var artField = -1, entryOff = -1;
    for (var off = 8; off <= 0x38; off += 4) {
      var ok = 0;
      for (var s = 0; s < samples.length; s++) {
        var h = samples[s].$handle;
        if (!h) { continue; }
        var cand = ptrInModuleAt(h, off);
        if (cand) { continue; }        // the artMethod slot must NOT be a
                                       // code pointer itself (it points to
                                       // an ArtMethod struct)
        try {
          var p = Memory.readPointer(h.add(off));
          if (p.isNull()) { continue; }
          for (var eo = 8; eo <= 0x28; eo += 4) {
            if (ptrInModuleAt(p, eo)) {
              ok++;
              break;
            }
          }
        } catch (e) {}
      }
      if (ok === samples.length) {
        artField = off;
        break;
      }
    }
    if (artField < 0) {
      log('offset discovery: artMethod slot not found - fn reads off');
      OFF_ARTMETHOD = -1;
      OFF_ENTRY = -1;
      return;
    }
    // layer 2: inside one sample's ArtMethod, find the entry-point slot
    var h0 = samples[0].$handle;
    var am = Memory.readPointer(h0.add(artField));
    for (var eo = 8; eo <= 0x28; eo += 4) {
      if (ptrInModuleAt(am, eo)) {
        entryOff = eo;
        break;
      }
    }
    OFF_ARTMETHOD = artField;
    OFF_ENTRY = entryOff;
    log('offset discovery: Method+0x' + off0hex(artField) +
        ' -> ArtMethod, entry+0x' + off0hex(entryOff < 0 ? 0 : entryOff) +
        (entryOff < 0 ? ' (entry not found - fn will be ?)' : ''));
  } catch (e) {
    log('offset discovery failed: ' + e);
    OFF_ARTMETHOD = -1;
    OFF_ENTRY = -1;
  }
}

function off0hex(n) {
  return n.toString(16);
}

function fnOf(m) {
  if (OFF_ARTMETHOD <= 0 || OFF_ENTRY <= 0) {
    return null;
  }
  try {
    var h = m.$handle;
    if (!h) { return null; }
    var am = Memory.readPointer(h.add(OFF_ARTMETHOD));
    if (am.isNull()) { return null; }
    var fn = Memory.readPointer(am.add(OFF_ENTRY));
    if (fn.isNull()) { return null; }
    return fn;
  } catch (e) {
    return null;
  }
}

/* The sweep: enumerate loaded classes, record every native method.
 * Pure reads + reflection - nothing is modified anywhere.  Runs ONLY when
 * the driver invokes it (post-warm-up); the offset discovery happens on
 * the first sweep call, never at script load. */
/* ------------------------------------------------------------------
 * raw-JNI sweep: the bridge's method marshalling is broken under the
 * deep stealth patch ($borrowClassHandle TypeError on every wrapper
 * METHOD call - runs 34183750848/34189152176), so getDeclaredMethods /
 * getModifiers / getName / getParameterTypes all go through the JNIEnv
 * vtable directly.  Slots from the authoritative jni.h struct order
 * (+4 reserved, anchors RegisterNatives@215 / GetObjectRefType@232):
 * FindClass@6, ExceptionClear@17, ExceptionOccurred@15, DeleteLocalRef@23,
 * GetObjectClass@31, GetMethodID@33, CallObjectMethod@34,
 * CallIntMethod@49, GetStaticMethodID@113, CallStaticObjectMethod@114,
 * NewStringUTF@167, GetStringUTFChars@169, ReleaseStringUTFChars@170,
 * GetArrayLength@171, GetObjectArrayElement@173, ExceptionCheck@228.
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
    ExceptionOccurred: fn(15, 'pointer', ['pointer']),
    ExceptionClear: fn(17, 'void', ['pointer']),
    DeleteLocalRef: fn(23, 'void', ['pointer', 'pointer']),
    GetObjectClass: fn(31, 'pointer', ['pointer', 'pointer']),
    GetMethodID: fn(33, 'pointer',
                    ['pointer', 'pointer', 'pointer', 'pointer']),
    CallObjectMethod: fn(34, 'pointer',
                         ['pointer', 'pointer', 'pointer']),
    CallIntMethod: fn(49, 'int', ['pointer', 'pointer', 'pointer']),
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
    GetArrayLength: fn(171, 'int', ['pointer', 'pointer']),
    GetObjectArrayElement: fn(173, 'pointer',
                              ['pointer', 'pointer', 'int']),
    ExceptionCheck: fn(228, 'int', ['pointer'])
  };
  return JNI;
}

function jstr(J, s) {
  try {
    if (s.isNull()) { return ''; }
    var p = J.GetStringUTFChars(J.env, s, ptr(0));
    if (p.isNull()) { return ''; }
    var r = Memory.readCString(p);
    J.ReleaseStringUTFChars(J.env, s, p);
    return r;
  } catch (e) {
    return '';
  }
}

/* Class object -> type descriptor (Ljava/lang/String; / I / [B ...) */
function classDescriptor(J, c, alloc) {
  try {
    var ccls = J.GetObjectClass(J.env, c);
    var nmid = J.GetMethodID(J.env, ccls, alloc('getName'),
                             alloc('()Ljava/lang/String;'));
    var s = J.CallObjectMethod(J.env, c, nmid);
    var nm = jstr(J, s);
    J.DeleteLocalRef(J.env, s);
    J.DeleteLocalRef(J.env, ccls);
    if (nm.charAt(0) === '[') {
      return nm.replace(/\./g, '/');
    }
    if (PRIM[nm]) { return PRIM[nm]; }
    return 'L' + nm.replace(/\./g, '/') + ';';
  } catch (e) {
    return '?';
  }
}

function methodSigJNI(J, m, mcls, alloc) {
  try {
    var ptmid = J.GetMethodID(J.env, mcls, alloc('getParameterTypes'),
                              alloc('()[Ljava/lang/Class;'));
    var pt = J.CallObjectMethod(J.env, m, ptmid);
    var s = '(';
    if (!pt.isNull()) {
      var n = J.GetArrayLength(J.env, pt);
      for (var i = 0; i < n; i++) {
        var c = J.GetObjectArrayElement(J.env, pt, i);
        s += classDescriptor(J, c, alloc);
        J.DeleteLocalRef(J.env, c);
      }
      J.DeleteLocalRef(J.env, pt);
    }
    var rtmid = J.GetMethodID(J.env, mcls, alloc('getReturnType'),
                              alloc('()Ljava/lang/Class;'));
    var rt = J.CallObjectMethod(J.env, m, rtmid);
    s += ')' + (rt.isNull() ? 'V' : classDescriptor(J, rt, alloc));
    if (!rt.isNull()) {
      J.DeleteLocalRef(J.env, rt);
    }
    return s;
  } catch (e) {
    return '?';
  }
}

function handleOf(w) {
  try {
    if (w) {
      if (w.$handle) { return w.$handle; }
      if (w.$h) { return w.$h; }
    }
  } catch (e) {}
  return null;
}

function loaderHandles() {
  var out = [];
  var seen = {};
  function add(h) {
    var key = String(h);
    if (!seen[key]) {
      seen[key] = true;
      out.push(h);
    }
  }
  try {
    var h = handleOf(Java.classFactory.loader);
    if (h) { add(ptr(h)); }
  } catch (e) {}
  try {
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        var lh = handleOf(loader);
        if (lh) { add(ptr(lh)); }
      },
      onComplete: function () {}
    });
  } catch (e) {}
  return out;
}

function sweep(budgetMs) {
  if (swept) {
    return 'already';
  }
  swept = true;
  var t0 = Date.now();
  var J = null;
  var alloc = null;
  var forNameMID = null;
  var clsClass = null;
  var loaders = [];
  try {
    var env = Java.vm.getEnv();
    J = jniInit(env.handle);
    alloc = function (s) { return Memory.allocUtf8String(s); };
    clsClass = J.FindClass(J.env, alloc('java/lang/Class'));
    forNameMID = J.GetStaticMethodID(
        J.env, clsClass, alloc('forName'),
        alloc('(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;'));
    if (clsClass.isNull() || forNameMID.isNull()) {
      throw new Error('forName setup failed');
    }
    loaders = loaderHandles();
    log('sweep setup: ' + loaders.length + ' loader(s)');
  } catch (e) {
    log('sweep setup failed: ' + e);
    return 'error';
  }
  var classes = [];
  try {
    classes = Java.enumerateLoadedClassesSync();
  } catch (e) {
    log('enumerateLoadedClasses failed: ' + e);
    return 'error';
  }
  log('sweep: ' + classes.length + ' loaded classes');
  var budget = budgetMs || 300000;
  var seen = 0;
  for (var ci = 0; ci < classes.length; ci++) {
    if (Date.now() - t0 > budget) {
      log('sweep: budget exhausted at class ' + ci + '/' + classes.length);
      break;
    }
    var name = classes[ci];
    var js = J.NewStringUTF(J.env, alloc(name));
    var cls = ptr(0);
    for (var li = 0; li < loaders.length; li++) {
      var r = J.CallStaticObjectMethod(J.env, clsClass, forNameMID,
                                       js, 0, loaders[li]);
      if (J.ExceptionCheck(J.env) === 0) {
        cls = r;
        break;
      }
      J.ExceptionClear(J.env);
    }
    J.DeleteLocalRef(J.env, js);
    if (cls.isNull()) {
      continue;               // not loadable from this classloader set
    }
    try {
      var dmid = J.GetMethodID(J.env, cls, alloc('getDeclaredMethods'),
                               alloc('()[Ljava/lang/reflect/Method;'));
      var arr = J.CallObjectMethod(J.env, cls, dmid);
      if (J.ExceptionCheck(J.env) !== 0) {
        J.ExceptionClear(J.env);
        J.DeleteLocalRef(J.env, cls);
        continue;
      }
      if (!arr.isNull()) {
        var n = J.GetArrayLength(J.env, arr);
        for (var i = 0; i < n; i++) {
          var m = J.GetObjectArrayElement(J.env, arr, i);
          var mcls = J.GetObjectClass(J.env, m);
          var modmid = J.GetMethodID(J.env, mcls, alloc('getModifiers'),
                                     alloc('()I'));
          var mods = J.CallIntMethod(J.env, m, modmid);
          if ((mods & 0x100) !== 0) {   // Modifier.NATIVE
            var nmid = J.GetMethodID(J.env, mcls, alloc('getName'),
                                     alloc('()Ljava/lang/String;'));
            var ns = J.CallObjectMethod(J.env, m, nmid);
            var mname = jstr(J, ns);
            J.DeleteLocalRef(J.env, ns);
            var rec = {
              name: mname,
              sig: methodSigJNI(J, m, mcls, alloc),
              fn: '?',
              mod: '<pending>',
              off: '?'
            };
            record(name, rec);
          }
          J.DeleteLocalRef(J.env, mcls);
          J.DeleteLocalRef(J.env, m);
        }
        J.DeleteLocalRef(J.env, arr);
      }
      seen++;
    } catch (e) {
      // one class must not kill the sweep
      try { J.ExceptionClear(J.env); } catch (ce) {}
    }
    J.DeleteLocalRef(J.env, cls);
  }
  var total = totalMethods();
  log('sweep done: ' + seen + ' classes visited, ' + total +
      ' native methods recorded in ' + (Date.now() - t0) + 'ms');
  send({ type: 'rn_swept', classes_seen: seen, native_methods: total,
         ms: Date.now() - t0 });
  return 'ok';
}

function activate() {
  if (activated) {
    return;
  }
  if (!isTarget()) {
    return;
  }
  activated = true;
  // NOTE (matrix runs 34175793717/34176267014): NO Java.perform here, no
  // reflection, nothing at load time.  The packer's init window (the
  // first ~2.5s after resume) detects ANY agent-side Java activity -
  // even Java.use('android.util.Log') + getDeclaredMethods at the gate
  // kills the process (L4 dead), while the empty script stays alive.
  // Every Java operation (offset discovery included) is deferred to the
  // driver-triggered sweep() that runs post-warm-up, minutes after the
  // packer finished its boot.
  log('active in ' + cmdline() + ' pid=' + Process.id +
      ' (pure-rpc: no load-time Java, nothing modified)');
}

setImmediate(function () {
  try {
    activate();
  } catch (e) {
    log('activate: ' + e);
  }
});

/* rpc surface consumed by unpack/frida_phase2_driver.py:
 *  sweep(budgetMs) - run the post-hoc enumeration (call AFTER warm-up!)
 *  count/classes/table - same contract as the hooked version
 */
rpc.exports = {
  sweep: function (budgetMs) {
    var r = 'error';
    Java.perform(function () {
      r = sweep(budgetMs);
    });
    return r;
  },
  count: function () {
    return totalMethods();
  },
  classes: function () {
    var out = [];
    for (var cls in RN) {
      if (Object.prototype.hasOwnProperty.call(RN, cls)) out.push(cls);
    }
    return out;
  },
  table: function () {
    var out = {};
    for (var cls in RN) {
      if (Object.prototype.hasOwnProperty.call(RN, cls)) {
        var rows = [];
        var bucket = RN[cls];
        for (var k in bucket) {
          if (Object.prototype.hasOwnProperty.call(bucket, k)) {
            rows.push(bucket[k]);
          }
        }
        out[cls] = rows;
      }
    }
    return out;
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
