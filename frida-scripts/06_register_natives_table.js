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
 * Pure reads + reflection - nothing is modified anywhere. */
function sweep(budgetMs) {
  if (swept) {
    return 'already';
  }
  swept = true;
  var t0 = Date.now();
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
    var cls = null;
    try {
      cls = Java.use(name).class;
    } catch (e) {
      continue;               // not loadable from this classloader set
    }
    try {
      var methods = cls.getDeclaredMethods();
      for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var mods;
        try {
          mods = m.getModifiers();
        } catch (e) {
          continue;
        }
        if ((mods & 0x100) === 0) {
          continue;           // not native
        }
        var mname;
        try {
          mname = String(m.getName());
        } catch (e) {
          continue;
        }
        var rec = {
          name: mname,
          sig: sigOf(m),
          fn: '?',
          mod: '<unknown>',
          off: '?'
        };
        var fn = fnOf(m);
        if (fn) {
          var mod = Process.findModuleByAddress(fn);
          rec.fn = String(fn);
          rec.mod = mod ? mod.name : '<anon>';
          rec.off = mod ? '0x' + fn.sub(mod.base).toString(16) : '?';
        }
        record(name, rec);
      }
      seen++;
    } catch (e) {
      // one class must not kill the sweep
    }
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
  log('active in ' + cmdline() + ' pid=' + Process.id +
      ' (observe-only: nothing is hooked, nothing is modified)');
  Java.perform(function () {
    try {
      discoverOffsets();
    } catch (e) {
      log('discoverOffsets: ' + e);
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
