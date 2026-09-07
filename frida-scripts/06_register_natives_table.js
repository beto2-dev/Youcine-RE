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
 * HOW: primary = hook the art::JNI<false/true>::RegisterNatives symbols in
 * libart.so (mangled _ZN3art...RegisterNatives..., dedup by address so the
 * fast and CheckJNI variants of the same address collapse).  Fallback if
 * libart carries no such symbols (stripped) = the JNIEnv function table:
 * *env is a JNINativeInterface* (the first field of JNIEnv), and
 * RegisterNatives sits at table slot 215.  Index 215 documented from the
 * JNI spec's JNINativeInterface layout (0-based): 4 reserved pointers at
 * 0..3, GetVersion at 4, ... RegisterNatives at 215, table ends at
 * GetObjectRefType (232).
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

// className -> { 'name|sig' -> rec } (plain objects: ES5-safe + JSON-able;
// Map would break ancient duktape-based frida runtimes)
var RN = {};
var JClass = null; // cached java.lang.Class wrapper for onEnter casts

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

function attachRegisterNatives(addr, label) {
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        // Runs on the REGISTERING thread, which is JNI-attached by
        // definition (it is calling a JNI function right now), so
        // Java.cast on the jclass is legal.
        try {
          this.rnClass = null;
          var count = args[3].toInt32();
          var className = 'jclass@' + args[1];
          try {
            className = String(Java.cast(args[1], JClass).getName());
          } catch (ce) {
            // Java bridge not ready / not a Class yet: keep the raw form
          }
          this.rnClass = className;
          // sanity: a garbage count means a garbage pointer - never touch it
          if (!(count > 0 && count <= 10000)) {
            log('skipping ' + label + ' count=' + count + ' class=' + className);
            return;
          }
          var ps = Process.pointerSize;
          var recs = [];
          for (var i = 0; i < count; i++) {
            try {
              var base = args[2].add(i * 3 * ps);
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
        } catch (e) {
          log('onEnter: ' + e);
        }
      },
      onLeave: function (retval) {
        try {
          var r = retval.toInt32();
          if (r !== 0) {
            send({
              type: 'rn_warn',
              ret: r,
              class: this.rnClass || '?',
              via: label
            });
          }
        } catch (e) {
          // never crash the caller on the way out
        }
      }
    });
    log('hooked RegisterNatives via ' + label + ' @ ' + addr);
    return true;
  } catch (e) {
    log('attach failed ' + label + ' @ ' + addr + ': ' + e);
    return false;
  }
}

function installHooks() {
  var hooked = 0;
  try {
    var libart = Process.getModuleByName('libart.so');
    var seen = {}; // address -> true: dedup (CheckJNI may alias the impl)
    var syms = libart.enumerateSymbols();
    for (var i = 0; i < syms.length; i++) {
      var s = syms[i];
      if (!s || !s.name) {
        continue;
      }
      if (s.name.indexOf('_ZN3art') !== 0) {
        continue;
      }
      if (s.name.indexOf('RegisterNatives') < 0) {
        continue;
      }
      if (s.type && s.type !== 'function' && s.type !== 'unknown') {
        continue;
      }
      var key = String(s.address);
      if (seen[key]) {
        continue;
      }
      seen[key] = true;
      if (attachRegisterNatives(s.address, s.name)) {
        hooked++;
      }
    }
  } catch (e) {
    log('libart symbol scan: ' + e);
  }
  if (hooked === 0) {
    // FALLBACK: hook slot 215 of the JNIEnv function table directly.
    // *env (the first field of JNIEnv) is the JNINativeInterface* table;
    // RegisterNatives is table index 215 (JNI spec function table).
    try {
      log('no libart RegisterNatives symbols - using JNIEnv table slot 215');
      var env = Java.vm.getEnv();
      var table = env.handle.readPointer();
      var ps = Process.pointerSize;
      var fn = table.add(215 * ps).readPointer();
      if (attachRegisterNatives(fn, 'JNIEnv[215]')) {
        hooked++;
      }
    } catch (e) {
      log('JNIEnv table fallback: ' + e);
    }
  }
  try {
    send({ type: 'rn_ready', hooked: hooked });
  } catch (se) {}
  log('installHooks: ' + hooked + ' RegisterNatives hook(s) live');
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

setImmediate(activate);
setInterval(activate, 500);

rpc.exports = {
  count: function () {
    try {
      return totalMethods();
    } catch (e) {
      return 0;
    }
  },
  classes: function () {
    try {
      var n = 0;
      for (var cls in RN) {
        if (Object.prototype.hasOwnProperty.call(RN, cls)) n++;
      }
      return n;
    } catch (e) {
      return 0;
    }
  },
  table: function () {
    // plain JSON-able {className: [{name, sig, fn, mod, off}]}
    var out = {};
    try {
      for (var cls in RN) {
        if (!Object.prototype.hasOwnProperty.call(RN, cls)) {
          continue;
        }
        var bucket = RN[cls];
        var arr = [];
        for (var k in bucket) {
          if (Object.prototype.hasOwnProperty.call(bucket, k)) {
            arr.push(bucket[k]);
          }
        }
        out[cls] = arr;
      }
    } catch (e) {
      log('table: ' + e);
    }
    return out;
  }
};
