/*
 * ijiami-static/capture_aes_key.js — Frida AES key-material capture for
 * YouCine 1.17.6 (com.world.youcinemobile) packed with iJiami
 * ("ijiami SecLLVM compiler 1.7.4.20" in libexec.so).
 *
 * Goal: the AES key that decrypts assets/ijiami.dat is derived inside the
 * SecLLVM-obfuscated libexec.so (static-analysis/ghidra-exports/
 * FUN_0005d480-engine.txt); dat_aes_probe.py proved the header ascii-hex
 * string is NOT the key. This script captures real key material at the
 * moment any AES implementation in the process is keyed.
 *
 * Two capture strategies:
 *   1. hook every AES key-material entry point in every module as modules
 *      appear (OpenSSL/BoringSSL AES_set_*_key + EVP_*Init*, mbedTLS,
 *      rijndael, tiny-AES-c), by dynamic export AND by internal symbol
 *      (enumerateSymbols — unstripped static builds);
 *   2. sweep the libexec.so module range for the AES S-box / inverse
 *      S-box byte patterns: hits are custom AES table candidates; Ghidra
 *      xrefs to those addresses reveal the (custom) key-setup function to
 *      hook (FUN_0005d480's family) or to breakpoint.
 *
 * Events via send() (consumed by the phase-2 driver, unpack/
 * frida_phase2_driver.py from agent 2-a, or `frida ... -l` on the CLI):
 *   {type:'aes_key',  fn, module, key, bits, iv, note}
 *   {type:'aes_table', module, address, pattern}
 * File sink (best effort): /data/local/tmp/youcine_re_phase2/keys.jsonl
 *
 * Usage (standalone):
 *   frida -U -f com.world.youcinemobile \
 *         -l ijiami-static/capture_aes_key.js --no-pause
 * or together with the ptrace bypass:
 *   frida -U -f com.world.youcinemobile \
 *         -l frida-scripts/02_bypass_ptrace.js \
 *         -l ijiami-static/capture_aes_key.js --no-pause
 *
 * Style: ES5-safe (no arrow functions, let/const, template literals).
 * NEVER crash the app: every hook/read is wrapped in try/catch.
 */
'use strict';

var TARGET = 'com.world.youcinemobile';
var OUT_DIR = '/data/local/tmp/youcine_re_phase2';
var OUT_FILE = OUT_DIR + '/keys.jsonl';
var PREFIX = '[aeskey]';

var ACTIVATED = false;
var HOOKED = {};          // "module!fn@addr" -> true
var SCANNED_MODULES = {}; // "name@base" -> true
var BUFFERED = [];        // lines waiting for a working file sink
var PERSISTED = {};       // line -> true (dedupe native/java sinks)
var JAVA_READY = false;

/* AES key-material entry points.
 * [symbol, keyArgIdx, bitsArgIdx (-1 unknown), ivArgIdx (-1 none)] */
var HOOKS = [
  { name: 'AES_set_encrypt_key', key: 0, bits: 1, iv: -1 },
  { name: 'AES_set_decrypt_key', key: 0, bits: 1, iv: -1 },
  { name: 'EVP_EncryptInit_ex', key: 3, bits: -1, iv: 4 },
  { name: 'EVP_DecryptInit_ex', key: 3, bits: -1, iv: 4 },
  { name: 'EVP_CipherInit_ex', key: 3, bits: -1, iv: 4 },
  { name: 'EVP_EncryptInit', key: 3, bits: -1, iv: 4 },
  { name: 'EVP_DecryptInit', key: 3, bits: -1, iv: 4 },
  { name: 'EVP_CipherInit', key: 3, bits: -1, iv: 4 },
  { name: 'mbedtls_aes_setkey_enc', key: 1, bits: 2, iv: -1 },
  { name: 'mbedtls_aes_setkey_dec', key: 1, bits: 2, iv: -1 },
  { name: 'rijndaelKeySetupEnc', key: 0, bits: -1, iv: -1 },
  { name: 'rijndaelKeySetupDec', key: 0, bits: -1, iv: -1 },
  /* tiny-AES-c is the most common AES in statically-linked obfuscated
   * builds (AES_init_ctx(ctx, key), AES_init_ctx_iv(ctx, key, iv)) */
  { name: 'AES_init_ctx', key: 1, bits: -1, iv: -1 },
  { name: 'AES_init_ctx_iv', key: 1, bits: -1, iv: 2 }
];

/* Modules worth an enumerateSymbols() pass (internal/unstripped symbols).
 * Every loaded module still gets the cheap findExportByName() pass. */
var SYMBOL_DEEP_MODULES = [
  'libexec.so', 'libexecmain.so',
  'libijmDataEncryption.so',
  'libcrypto.so', 'libssl.so', 'libmbedcrypto.so', 'libc.so'
];

/* Modules swept for the AES S-box byte patterns. */
var SBOX_SCAN_MODULES = ['libexec.so', 'libexecmain.so'];

var AES_SBOX_HEAD = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76';
var AES_INV_SBOX_HEAD = '52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb';

var HEX = '0123456789abcdef';

function log(msg) {
  console.log(PREFIX + ' ' + msg);
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

function toHex(ab) {
  try {
    var u8 = new Uint8Array(ab);
    var out = '';
    for (var i = 0; i < u8.length; i++) {
      out += HEX[(u8[i] >> 4) & 0xf] + HEX[u8[i] & 0xf];
    }
    return out;
  } catch (e) {
    return '';
  }
}

/* ------------------------------------------------------------------ hooks */

function onKeyMaterial(args, spec, moduleName) {
  try {
    var bits = 0;
    if (spec.bits >= 0) {
      bits = args[spec.bits].toInt32();
    }
    var readLen = 32;                       // EVP: length unknown
    if (bits === 128 || bits === 192 || bits === 256) {
      readLen = bits / 8;
    }
    var keyHex = '';
    var kp = args[spec.key];
    if (kp !== null && !kp.isNull()) {
      try {
        keyHex = toHex(Memory.readByteArray(kp, readLen));
      } catch (e2) {
        keyHex = '';
      }
    }
    if (!keyHex) {
      return;                                // null/unreadable key (EVP can
    }                                        // be called with key=NULL)
    var ivHex = '';
    if (spec.iv >= 0) {
      try {
        var ivp = args[spec.iv];
        if (ivp !== null && !ivp.isNull()) {
          ivHex = toHex(Memory.readByteArray(ivp, 16));
        }
      } catch (e3) {
        ivHex = '';
      }
    }
    var note = bits ? '' : 'key length unknown (EVP-style) - 32B window; ' +
      'also try its first 16 bytes offline';
    var ev = {
      type: 'aes_key',
      fn: spec.name,
      module: moduleName,
      key: keyHex,
      bits: bits,
      iv: ivHex,
      note: note
    };
    try {
      send(ev);
    } catch (e4) {}
    log('KEY ' + spec.name + ' module=' + moduleName +
        ' bits=' + bits + ' key=' + keyHex + ' iv=' + ivHex);
    record(ev);
  } catch (e) {
    log('onKeyMaterial error: ' + e);
  }
}

function attachAt(addr, spec, moduleName) {
  var key = moduleName + '!' + spec.name + '@' + addr;
  if (HOOKED[key]) {
    return;
  }
  HOOKED[key] = true;
  try {
    Interceptor.attach(addr, (function (sp, mod) {
      return {
        onEnter: function (args) {
          try {
            onKeyMaterial(args, sp, mod);
          } catch (e) {
            log('hook body error: ' + e);
          }
        }
      };
    })(spec, moduleName));
    log('hooked ' + key);
  } catch (e) {
    log('hook failed ' + key + ': ' + e);
  }
}

function hookModuleByExports(mod) {
  for (var i = 0; i < HOOKS.length; i++) {
    try {
      var addr = Module.findExportByName(mod ? mod.name : null,
                                         HOOKS[i].name);
      if (addr) {
        attachAt(addr, HOOKS[i], mod ? mod.name : '<any>');
      }
    } catch (e) {}
  }
}

function hookModuleBySymbols(mod) {
  var deep = false;
  for (var i = 0; i < SYMBOL_DEEP_MODULES.length; i++) {
    if (mod.name.indexOf(SYMBOL_DEEP_MODULES[i]) !== -1) {
      deep = true;
      break;
    }
  }
  if (!deep) {
    return;
  }
  var symbols = [];
  try {
    symbols = mod.enumerateSymbols();
  } catch (e) {
    log('enumerateSymbols failed for ' + mod.name + ': ' + e);
    return;
  }
  for (var s = 0; s < symbols.length; s++) {
    var sym = symbols[s];
    if (sym.type !== 'function') {
      continue;
    }
    for (var h = 0; h < HOOKS.length; h++) {
      if (sym.name === HOOKS[h].name) {
        attachAt(sym.address, HOOKS[h], mod.name);
      }
    }
  }
}

/* -------------------------------------------------- S-box pattern sweep */

function scanModuleRangesForTables(mod) {
  var modEnd = null;
  try {
    modEnd = mod.base.add(mod.size);
  } catch (e) {
    return;
  }
  var patterns = [
    { pat: AES_SBOX_HEAD, note: 'AES S-box (forward)' },
    { pat: AES_INV_SBOX_HEAD, note: 'AES inverse S-box' }
  ];
  var ranges = [];
  try {
    ranges = Process.enumerateRanges('r--');
  } catch (e) {
    return;
  }
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    try {
      if (r.base.compare(mod.base) < 0 || r.base.compare(modEnd) >= 0) {
        continue;
      }
    } catch (e2) {
      continue;
    }
    for (var p = 0; p < patterns.length; p++) {
      try {
        (function (range, pattern) {
          Memory.scan(range.base, range.size, pattern.pat, {
            onMatch: function (address, size) {
              try {
                send({
                  type: 'aes_table',
                  module: mod.name,
                  address: String(address),
                  pattern: pattern.note
                });
                log('TABLE ' + pattern.note + ' in ' + mod.name +
                    ' @ ' + address +
                    ' (Ghidra xrefs to this address find the custom ' +
                    'key-setup function)');
              } catch (e) {
                log('table match report error: ' + e);
              }
            },
            onError: function (reason) {
              log('scan range error: ' + reason);
            },
            onComplete: function () {}
          });
        })(r, patterns[p]);
      } catch (e3) {
        log('scan failed for ' + mod.name + ': ' + e3);
      }
    }
  }
}

/* ---------------------------------------------------------- file sink */

function record(ev) {
  var line = '';
  try {
    line = JSON.stringify(ev);
  } catch (e) {
    return;
  }
  if (PERSISTED[line]) {
    return;
  }
  if (!nativeWrite(line)) {
    BUFFERED.push(line);
  }
}

function nativeWrite(line) {
  /* frida's File supports append ('a') on most builds; if it throws we
   * fall back to buffering until Java is ready. */
  try {
    var f = new File(OUT_FILE, 'a');
    f.writeLine(line);
    f.flush();
    f.close();
    PERSISTED[line] = true;
    return true;
  } catch (e) {
    return false;
  }
}

function javaWrite(line) {
  try {
    var File = Java.use('java.io.File');
    File.$new(OUT_DIR).mkdirs();
    var FOS = Java.use('java.io.FileOutputStream');
    var JString = Java.use('java.lang.String');
    var fos = FOS.$new(OUT_FILE, true);     // append mode
    try {
      fos.write(JString.$new(line + '\n').getBytes());
    } finally {
      fos.close();
    }
    PERSISTED[line] = true;
    return true;
  } catch (e) {
    log('javaWrite failed: ' + e);
    return false;
  }
}

function flushBuffered() {
  var remaining = [];
  for (var i = 0; i < BUFFERED.length; i++) {
    if (!javaWrite(BUFFERED[i])) {
      remaining.push(BUFFERED[i]);
    }
  }
  BUFFERED = remaining;
}

function tryJavaSink() {
  if (JAVA_READY) {
    return;
  }
  try {
    Java.perform(function () {
      try {
        var File = Java.use('java.io.File');
        File.$new(OUT_DIR).mkdirs();
        JAVA_READY = true;
        log('java ready, key sink: ' + OUT_FILE);
        flushBuffered();
      } catch (e) {
        /* Java VM up but sink not usable yet — retry next tick */
      }
    });
  } catch (e) {}
}

/* ----------------------------------------------------------- rescan loop */

var rescanCount = 0;

function rescanModules() {
  var mods = [];
  try {
    mods = Process.enumerateModules();
  } catch (e) {
    return;
  }
  for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    var id = m.name + '@' + m.base;
    if (SCANNED_MODULES[id]) {
      continue;
    }
    SCANNED_MODULES[id] = true;
    hookModuleByExports(m);
    hookModuleBySymbols(m);
    for (var s = 0; s < SBOX_SCAN_MODULES.length; s++) {
      if (m.name.indexOf(SBOX_SCAN_MODULES[s]) !== -1) {
        scanModuleRangesForTables(m);
      }
    }
  }
}

function startRescans() {
  rescanModules();                          // immediate first sweep
  var timer = setInterval(function () {
    rescanCount += 1;
    try {
      rescanModules();
    } catch (e) {
      log('rescan error: ' + e);
    }
    if (rescanCount >= 30) {                // every 2 s for the first 60 s
      clearInterval(timer);
      log('rescan loop done after 60 s (' +
          Object.keys(SCANNED_MODULES).length + ' modules seen)');
    }
  }, 2000);
}

/* ------------------------------------------------------------- activate */

function activate() {
  if (ACTIVATED) {
    return;
  }
  if (!isTarget()) {
    return;
  }
  ACTIVATED = true;
  log('active in ' + cmdline());
  try {
    hookModuleByExports(null);              // global export search
  } catch (e) {
    log('global export sweep error: ' + e);
  }
  startRescans();
  setInterval(tryJavaSink, 1000);
}

setImmediate(activate);
setInterval(activate, 500);
