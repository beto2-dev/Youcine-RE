/*
 * Youcine-RE - phase 2: capture the COMPLETE RegisterNatives table.
 * Run against the ORIGINAL packed APK (the content-gated engine only
 * registers on the byte-exact original - run 34133100459 is the proven
 * environment: native-arm64 redroid + original APK).
 *
 * WHY: the ~805 ACC_NATIVE methods (17 com.arialyy.*, 424
 * com.mobile.brasiltv.*, 53 com.facebook.*, EFS, ...) receive their JNI
 * implementations ONLY at runtime from libexec.so's content-gated engine.
 * The packer-free rebuild v5 executes every non-protected layer and then
 * dies at the first VMP-protected method (App.onCreate:139 -> Aria.init ->
 * SqlHelper.getDb, runs 34166188171 / 34166250339): removing the packer
 * removed the only registrar.  This script records
 * class -> {name, signature, fnPtr(module+offset)} for every
 * RegisterNatives call, so the later de-natify bridge can map each native
 * back to its Java-visible declaration (open-source families get Java
 * bodies; the vendor's 424 need a registrar shim).
 *
 * HOW (run 34175381036 matrix verdict): Interceptor.attach on the
 * art::JNI::RegisterNatives function body - via symbol scan OR via the
 * vtable-resolved address - is an INLINE CODE PATCH on libart.so and
 * iJiami's VMP integrity-checks libart's code and kills the process
 * (L4: agent+06 = dead; agent alone = alive).  libart's CODE is never
 * touched here: the shared JNINativeInterface function table (reachable
 * as *env, i.e. the first field of any JNIEnv) has RegisterNatives at
 * slot 215 (JNI spec table, 0-based, 4 reserved -> GetVersion@4 ->
 * ... -> RegisterNatives@215 -> GetObjectRefType@232).  We copy nothing
 * and patch nothing in code - we mprotect the ONE table slot writable
 * and swap the function POINTER for a NativeCallback that parses the
 * JNINativeMethod array, records it, and forwards to the original.
 * That is a pure DATA modification - invisible to the prologue checksum
 * the packer runs on executable pages.
 *
 * The JNINativeMethod array (arg 2) is {const char* name; const char*
 * signature; void* fnPtr} - 3 pointers per entry, count in arg 3.  libexec
 * may RE-register methods as classes re-materialize, so the table keeps
 * the LATEST fnPtr per (class, name, signature).
 *
 * Style follows 01_unpack_ijiami_dex.js: /proc/self/cmdline target gating
 * with activation retry, 'use strict', and total try/catch discipline - a
 * failing hook must never crash the packed process (one shot per run).
 */
'use strict';

var TARGET = 'com.world.youcinemobile';
var activated = false;
var SLOT = 215;      // JNINativeInterface.RegisterNatives

// className -> { 'name|sig' -> rec } (plain objects: ES5-safe + JSON-able;
// Map would break ancient duktape-based frida runtimes)
var RN = {};
var JClass = null; // cached java.lang.Class wrapper for name casts

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
  // dedup by class+name+sig; the plain-object assignment keeps the LATEST
  // fn (libexec re-registers as classes re-materialize)
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

/* Parse + record a JNINativeMethod array; runs INSIDE our replacement
 * callback, on the REGISTERING thread (which is JNI-attached by
 * definition - it is calling a JNI function right now), so Java.cast on
 * the jclass is legal.  Returns the row records for the send() event. */
function parseMethods(env, jclass, methods, count) {
  var recs = [];
  var className = 'jclass@' + jclass;
  try {
    className = String(Java.cast(jclass, JClass).getName());
  } catch (ce) {
    // Java bridge not ready / not a Class yet: keep the raw form
  }
  // sanity: a garbage count means a garbage pointer - never touch it
  if (!(count > 0 && count <= 10000)) {
    log('skipping count=' + count + ' class=' + className);
    return recs;
  }
  var ps = Process.pointerSize;
  for (var i = 0; i < count; i++) {
    try {
      var base = methods.add(i * 3 * ps);
      var namePtr = base.readPointer();
      var sigPtr = base.add(ps).readPointer();
      var fnPtr = base.add(2 * ps).readPointer();
      if (namePtr.isNull() || sigPtr.isNull() || fnPtr.isNull()) {
        continue;
      }
      var name = namePtr.readCString();
      var sig = sigPtr.readCString();
      if (name === null || sig === null) {
        continue;
      }
      var mod = Process.findModuleByAddress(fnPtr);
      var rec = {
        name: name,
        sig: sig,
        fn: String(fnPtr),
        mod: mod ? mod.name : '<anon>',
        off: mod ? '0x' + fnPtr.sub(mod.base).toString(16) : '?'
      };
      record(className, rec);
      recs.push(rec);
    } catch (e) {
      // one bad row must not kill the remaining count-1 rows
    }
  }
  send({ type: 'rn', class: className, count: count, methods: recs });
  return recs;
}

/* Swap JNINativeInterface slot 215 for our NativeCallback.  The table is
 * SHARED by every JNIEnv of the VM, so one swap covers all threads. */
function patchVtableSlot() {
  var env = Java.vm.getEnv();
  var ps = Process.pointerSize;
  var table = env.handle.readPointer();      // *env == JNINativeInterface*
  var slotAddr = table.add(SLOT * ps);
  var original = slotAddr.readPointer();
  if (original.isNull()) {
    throw new Error('slot ' + SLOT + ' is NULL');
  }
  var forward = new NativeFunction(
    original, 'int', ['pointer', 'pointer', 'pointer', 'int']);
  Memory.protect(slotAddr, ps, 'rw-');
  slotAddr.writePointer(new NativeCallback(
    function (jniEnv, jclass, methods, n) {
      var ret = 0;
      try {
        var count = n;
        try {
          count = n.toInt32();
        } catch (te) {
          /* older runtimes pass a raw number */
        }
        parseMethods(jniEnv, jclass, methods, count);
      } catch (e) {
        // NEVER crash the registering thread
        try { log('callback: ' + e); } catch (le) {}
      }
      try {
        ret = forward(jniEnv, jclass, methods, n);
        if (ret !== 0) {
          send({ type: 'rn_warn', ret: ret, via: 'vtable[215]' });
        }
      } catch (e) {
        try { log('forward: ' + e); } catch (le) {}
      }
      return ret;
    },
    'int', ['pointer', 'pointer', 'pointer', 'int']));
  log('vtable slot ' + SLOT + ' swapped: original ' + original +
      ' -> callback (libart code untouched)');
  return true;
}

function installHooks() {
  var ok = false;
  try {
    ok = patchVtableSlot();
  } catch (e) {
    log('vtable slot swap failed: ' + e);
  }
  try {
    send({ type: 'rn_ready', hooked: ok ? 1 : 0, mode: 'vtable-slot' });
  } catch (se) {}
  log('installHooks: ' + (ok ? 'RegisterNatives capture live (data-only)' :
      'FAILED'));
}

function activate() {
  if (activated) {
    return;
  }
  if (!isTarget()) {
    return;
  }
  activated = true;
  log('active in ' + cmdline() + ' pid=' + Process.id);
  Java.perform(function () {
    try {
      JClass = Java.use('java.lang.Class');
    } catch (e) {
      log('java.lang.Class unavailable: ' + e);
    }
    try {
      installHooks();
    } catch (e) {
      log('installHooks: ' + e);
    }
  });
}

setImmediate(function () {
  try {
    activate();
  } catch (e) {
    log('activate: ' + e);
  }
});

// late re-arm: the gate runs before the app's classloader exists; if the
// first attempt failed for timing reasons try once more after 10s
setTimeout(function () {
  try {
    if (!activated) {
      activate();
    }
  } catch (e) {
    log('re-arm: ' + e);
  }
}, 10000);

/* rpc surface consumed by unpack/frida_phase2_driver.py */
rpc.exports = {
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
