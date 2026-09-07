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
  var ClassLoader = Java.use('java.lang.ClassLoader');
  function add(l) {
    try {
      var casted = Java.cast(l, ClassLoader);
      var key = String(casted.$h);
      if (seen[key]) {
        return;
      }
      seen[key] = true;
      out.push(casted);
    } catch (e) {
      // keep going - a broken loader entry loses one candidate, not the sweep
    }
  }
  try {
    var main = Java.classFactory.loader;
    if (main) {
      add(main);
    }
  } catch (e) {
    log('classFactory.loader: ' + e);
  }
  try {
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        add(loader);
      },
      onComplete: function () {}
    });
  } catch (e) {
    log('enumerateClassLoaders: ' + e);
  }
  LOADERS = out;
  log('loader cascade: ' + out.length + ' classloader(s)');
  return out;
}

function warmupInner(names) {
  var stats = { ok: 0, notfound: 0, fail: 0, errors: [] };
  var total = names.length;
  var forName = null;
  var loaders = [];
  try {
    var ClassF = Java.use('java.lang.Class');
    forName = ClassF.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');
    loaders = getLoaders();
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
    for (var li = 0; li < loaders.length; li++) {
      var attempt;
      try {
        // initialize=true: <clinit> must run so native libs load and
        // libexec's re-materialization gates actually fire
        forName(name, true, loaders[li]);
        attempt = 'ok';
      } catch (e) {
        attempt = classifyError(e);
        reason = errText(e);
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
