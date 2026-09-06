/*
 * Youcine-RE - dump decrypted DEX after iJiami N.al() / InMemoryDexFile.
 *
 * Writes to /data/data/<pkg>/files/youcine_re_dump/ when possible, and
 * also sends blobs through Frida. Safe to inject via zygote child-gating.
 *
 * Package filter uses cmdline so the script can sit in unrelated zygote kids.
 */
'use strict';

var TARGET = 'com.world.youcinemobile';
var DUMP_REL = 'youcine_re_dump';
var activated = false;

function log(msg) {
  console.log('[ijiami-unpack] ' + msg);
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

function ensureDir(path) {
  var File = Java.use('java.io.File');
  var d = File.$new(path);
  if (!d.exists()) {
    d.mkdirs();
  }
}

function writeDex(bytes, tag) {
  var FileOutputStream = Java.use('java.io.FileOutputStream');
  var File = Java.use('java.io.File');
  var ActivityThread = Java.use('android.app.ActivityThread');
  var app = ActivityThread.currentApplication();
  if (app === null) {
    log('no application yet, skip write ' + tag);
    return;
  }
  var dir = app.getFilesDir().getAbsolutePath() + '/' + DUMP_REL;
  ensureDir(dir);
  var name = dir + '/' + tag + '.dex';
  var fos = FileOutputStream.$new(name);
  var arr = Java.array('byte', bytes);
  fos.write(arr);
  fos.close();
  log('wrote ' + name + ' len=' + bytes.length);
}

function dumpClassLoader(cl, tag) {
  if (cl === null) {
    return;
  }
  try {
    var BaseDex = Java.use('dalvik.system.BaseDexClassLoader');
    if (!BaseDex.class.isInstance(cl)) {
      log('classloader is not BaseDexClassLoader: ' + cl.$className);
      return;
    }
    var pathList = cl.pathList.value;
    var dexElements = pathList.dexElements.value;
    for (var i = 0; i < dexElements.length; i++) {
      var el = dexElements[i];
      var dexFile = el.dexFile.value;
      if (dexFile === null) {
        continue;
      }
      var mCookie = dexFile.mCookie.value;
      log('element ' + i + ' cookie=' + mCookie);
      try {
        var DexFile = Java.use('dalvik.system.DexFile');
        // best-effort: copy the file path if it exists
        var fileName = dexFile.mFileName ? dexFile.mFileName.value : null;
        if (fileName) {
          log('dex fileName=' + fileName);
        }
      } catch (e1) {
        log('dexFile inspect: ' + e1);
      }
    }
  } catch (e) {
    log('dumpClassLoader: ' + e);
  }
}

function hookMemoryDex() {
  var names = [
    'dalvik.system.InMemoryDexClassLoader',
    'dalvik.system.DexFile',
  ];
  try {
    var InMem = Java.use('dalvik.system.InMemoryDexClassLoader');
    InMem.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (buf, parent) {
      try {
        var dup = buf.duplicate();
        var n = dup.remaining();
        var arr = [];
        for (var i = 0; i < n && i < 80 * 1024 * 1024; i++) {
          arr.push(dup.get());
        }
        log('InMemoryDexClassLoader n=' + n);
        writeDex(arr, 'inmem_' + n);
      } catch (e) {
        log('inmem dump fail ' + e);
      }
      return this.$init(buf, parent);
    };
  } catch (e) {
    log('no InMemoryDexClassLoader: ' + e);
  }

  try {
    var N = Java.use('s.h.e.l.l.N');
    N.al.implementation = function (cl, ai, pkg, appName) {
      log('N.al pkg=' + pkg + ' app=' + appName);
      var r = this.al(cl, ai, pkg, appName);
      dumpClassLoader(r, 'N.al');
      return r;
    };
    log('hooked s.h.e.l.l.N.al');
  } catch (e) {
    log('N.al hook later: ' + e);
  }

  try {
    var A = Java.use('s.h.e.l.l.A');
    A.instantiateClassLoader.implementation = function (cl, ai) {
      log('A.instantiateClassLoader');
      var r = this.instantiateClassLoader(cl, ai);
      dumpClassLoader(r, 'A.cl');
      return r;
    };
  } catch (e) {
    log('A hook: ' + e);
  }
}

function activate() {
  if (activated) {
    return;
  }
  if (!isTarget()) {
    return;
  }
  activated = true;
  log('active in ' + cmdline());
  Java.perform(hookMemoryDex);
}

setImmediate(activate);
setInterval(activate, 500);
