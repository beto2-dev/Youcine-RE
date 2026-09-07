/*
 * Youcine-RE - phase 2: in-process DEX census + native module memory dump.
 *
 * IMPORTANT / LIMITS: this script can only READ what the target process
 * itself can read.  The [anon:dalvik-DEX data] containers span several map
 * entries - big r--p pieces interleaved with small -wxp pieces (8-32 KiB,
 * NO read bit; run 34124326711..34129023827 evidence) - and in-process
 * reads of write-only pages fault.  The AUTHORITATIVE re-dumper therefore
 * stays unpack/dexdata_extract.py: out-of-process pread64 on
 * /proc/<pid>/mem uses FOLL_FORCE and crosses the -wxp pieces fine (it
 * also SIGSTOPs the app, which in-process reads obviously cannot).  This
 * script COMPLEMENTS it with (a) a live census of the DEX spans (how many,
 * how readable in-proc, dex magic + file_size per span) as before/after
 * warm-up evidence, and (b) memory images of the NATIVE modules
 * (libexec.so / libijmDataEncryption.so) which dexdata_extract.py cannot
 * dump: SecLLVM self-modifies, so the memory image != disk image, and the
 * phase-3 analysis needs the post-boot bytes.
 *
 * Artifacts land under /data/local/tmp/youcine_re_phase2/ (+ modules/).
 * If SELinux forbids the app writing there (shell_data_file), the script
 * falls back to the app's own files dir and reports the actual path via
 * send({type:'redump_devdir'}) and in every dumpmodule() result - the
 * driver pulls both.  All Java-dependent file writes degrade silently:
 * without a Java VM the script still returns the census/dump data.
 */
'use strict';

var DEVDIR = '/data/local/tmp/youcine_re_phase2/';
var MODDIR_SUFFIX = 'modules/';
var CHUNK_DEX = 64 * 1024;         // census probe granularity
var MAX_PROBE = 8 * 1024 * 1024;   // census: read at most 8 MiB per span
var GAP_TOLERANCE = 0x10000;       // 64 KiB - mirrors unpack/dexdata_extract.py
var CHUNK_MOD = 1024 * 1024;       // module dump chunk size

var ACTUAL_DIR = null; // DEVDIR or the app-files fallback
var DIRS_READY = false;

function log(msg) {
  console.log('[redump] ' + msg);
}

function javaOk() {
  try {
    return Java.available;
  } catch (e) {
    return false;
  }
}

function ptrToNum(p) {
  // NativePointer -> exact JS number (Android addresses < 2^53)
  return parseInt(p.toString(10), 10);
}

// ---------------------------------------------------------------------------
// /proc/self/maps via the Frida File API (readLine loop; a redroid maps
// file can exceed 100k lines, so a bounded loop with a hard safety cap)
// ---------------------------------------------------------------------------
function readMapsLines() {
  var lines = [];
  var f = null;
  try {
    f = new File('/proc/self/maps', 'r');
    while (lines.length < 200000) {
      var line = f.readLine();
      if (line === null || line === undefined || line === false || line === '') {
        break; // EOF (implementations return null or '' - handle both)
      }
      lines.push(line);
    }
  } catch (e) {
    log('readMaps: ' + e);
  } finally {
    try {
      if (f) {
        f.close();
      }
    } catch (e2) {}
  }
  return lines;
}

function parseMapLine(line) {
  // "7f1234000000-7f1234010000 r--p 00000000 fd:01 1234 [anon:dalvik-DEX data]"
  var dash = line.indexOf('-');
  if (dash <= 0) {
    return null;
  }
  var space = line.indexOf(' ', dash);
  if (space < 0) {
    return null;
  }
  var startS = line.substring(0, dash);
  var endS = line.substring(dash + 1, space);
  if (!/^[0-9a-fA-F]+$/.test(startS) || !/^[0-9a-fA-F]+$/.test(endS)) {
    return null;
  }
  var rest = line.substring(space + 1);
  var perms = rest.split(' ')[0] || '???';
  return { start: parseInt(startS, 16), end: parseInt(endS, 16), perms: perms };
}

// ---------------------------------------------------------------------------
// device dir handling (with SELinux-aware fallback)
// ---------------------------------------------------------------------------
function ensureDevDirs() {
  if (DIRS_READY) {
    return ACTUAL_DIR;
  }
  // Primary: the contract location. mkdirs is idempotent; a real write
  // probe decides whether untrusted_app may create files there at all.
  try {
    var File = Java.use('java.io.File');
    File.$new(DEVDIR).mkdirs();
    File.$new(DEVDIR + MODDIR_SUFFIX).mkdirs();
    var probe = File.$new(DEVDIR + '.probe');
    var created = probe.createNewFile();
    if (created || probe.exists()) {
      if (created) {
        probe.delete();
      }
      ACTUAL_DIR = DEVDIR;
      DIRS_READY = true;
      send({ type: 'redump_devdir', dir: ACTUAL_DIR, fallback: false });
      return ACTUAL_DIR;
    }
  } catch (e) {
    log('primary devdir probe failed: ' + e);
  }
  // Fallback: the app's own files dir (always writable for the app uid).
  try {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
    if (app !== null && app !== undefined) {
      var fb = String(app.getFilesDir().getAbsolutePath()) + '/youcine_re_phase2/';
      var File2 = Java.use('java.io.File');
      File2.$new(fb).mkdirs();
      File2.$new(fb + MODDIR_SUFFIX).mkdirs();
      ACTUAL_DIR = fb;
      DIRS_READY = true;
      log('using FALLBACK devdir: ' + fb);
      send({ type: 'redump_devdir', dir: ACTUAL_DIR, fallback: true });
      return fb;
    }
  } catch (e2) {
    log('fallback devdir failed: ' + e2);
  }
  // last resort: keep the contract path even if writes may fail
  ACTUAL_DIR = DEVDIR;
  DIRS_READY = true;
  return ACTUAL_DIR;
}

// ---------------------------------------------------------------------------
// byte helpers (ArrayBuffer -> signed JS array -> java byte[]), ES5-safe
// ---------------------------------------------------------------------------
function toSignedArray(ab) {
  var u8 = new Uint8Array(ab);
  var n = u8.length;
  var arr = new Array(n);
  for (var i = 0; i < n; i++) {
    var v = u8[i];
    arr[i] = v < 128 ? v : v - 256;
  }
  return arr;
}

function strToSigned(s) {
  // minimal UTF-8 encoder (JSON manifests are ASCII apart from exotic
  // module paths; BMP-only is fine for this purpose)
  var out = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  var signed = new Array(out.length);
  for (var j = 0; j < out.length; j++) {
    var v = out[j];
    signed[j] = v < 128 ? v : v - 256;
  }
  return signed;
}

function openRaf(path) {
  // RandomAccessFile 'rw' does NOT truncate: drop stale bytes from a
  // previous run so re-runs cannot leave a stale tail behind
  try {
    var JFile = Java.use('java.io.File');
    var old = JFile.$new(path);
    if (old.exists()) {
      old.delete();
    }
  } catch (de) {}
  try {
    var RAF = Java.use('java.io.RandomAccessFile');
    return RAF.$new(path, 'rw');
  } catch (e) {
    log('open ' + path + ': ' + e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// DEX census
// ---------------------------------------------------------------------------
function dexcensusInner() {
  var lines = readMapsLines();
  var entries = [];
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].indexOf('dalvik-DEX data') < 0) {
      continue;
    }
    var m = parseMapLine(lines[i]);
    if (m && m.end > m.start) {
      entries.push(m);
    }
  }
  entries.sort(function (a, b) {
    return a.start - b.start;
  });
  // group address-adjacent entries into spans (gap <= 64 KiB) - the small
  // -wxp pieces sit right between the big r--p ones and belong to the
  // same dex container (mirrors dexdata_extract.py GAP_TOLERANCE)
  var spans = [];
  var cur = null;
  for (var j = 0; j < entries.length; j++) {
    var e = entries[j];
    if (cur && e.start - cur.endNum <= GAP_TOLERANCE) {
      if (e.end > cur.endNum) {
        cur.endNum = e.end;
      }
      cur.pieces++;
    } else {
      if (cur) {
        spans.push(cur);
      }
      cur = { startNum: e.start, endNum: e.end, pieces: 1 };
    }
  }
  if (cur) {
    spans.push(cur);
  }

  var out = { spans: [], when: new Date().toISOString(), total_probe_readable: 0 };
  var totalReadable = 0;
  for (var k = 0; k < spans.length; k++) {
    var sp = spans[k];
    var len = sp.endNum - sp.startNum;
    var probeLen = Math.min(len, MAX_PROBE);
    var readable = 0;
    var holes = 0;
    var first = null;
    var nChunks = Math.ceil(probeLen / CHUNK_DEX);
    for (var c = 0; c < nChunks; c++) {
      var off = c * CHUNK_DEX;
      var n = Math.min(CHUNK_DEX, probeLen - off);
      var buf = null;
      try {
        buf = Memory.readByteArray(ptr('0x' + (sp.startNum + off).toString(16)), n);
      } catch (er) {
        buf = null; // -wxp no-read piece: exactly why the out-of-proc
                    // pread64/FOLL_FORCE dump stays authoritative
      }
      if (buf && buf.byteLength > 0) {
        readable += buf.byteLength;
        if (off === 0) {
          first = new Uint8Array(buf);
        }
      } else {
        holes++;
      }
    }
    totalReadable += readable;
    var magic = false;
    var dexSize = 0;
    if (first && first.length >= 36 &&
        first[0] === 0x64 && first[1] === 0x65 &&
        first[2] === 0x78 && first[3] === 0x0a) {
      // 'dex\n' magic + u32 file_size at header offset 32 (little endian)
      dexSize = (first[32] | (first[33] << 8) | (first[34] << 16) | (first[35] << 24)) >>> 0;
      if (dexSize >= 0x70 && dexSize <= 200 * 1024 * 1024) {
        magic = true;
      } else {
        dexSize = 0;
      }
    }
    out.spans.push({
      start: '0x' + sp.startNum.toString(16),
      end: '0x' + sp.endNum.toString(16),
      size: len,
      pieces: sp.pieces,
      readable: readable,
      holes: holes,
      dex_magic: magic,
      dex_size: dexSize
    });
  }
  out.total_probe_readable = totalReadable;
  return out;
}

// ---------------------------------------------------------------------------
// native module memory image dump
// ---------------------------------------------------------------------------
function dumpModuleInner(name, tag) {
  var mod = null;
  try {
    mod = Process.findModuleByName(name);
  } catch (e) {}
  if (!mod) {
    return { error: 'not loaded', module: name };
  }
  var t = tag || 'pre';
  var ranges = [];
  try {
    ranges = mod.enumerateRanges('---'); // '---' = every protection
  } catch (e) {
    log('enumerateRanges(' + name + '): ' + e);
  }
  try {
    ranges.sort(function (a, b) {
      return a.base.compare(b.base);
    });
  } catch (e) {
    log('sort ranges: ' + e);
  }

  var dir = javaOk() ? ensureDevDirs() : null;
  var path = null;
  var raf = null;
  var writeArr = null;
  if (dir) {
    path = dir + MODDIR_SUFFIX + name + '.' + t + '.mem';
    raf = openRaf(path);
    if (raf) {
      try {
        writeArr = raf.write.overload('[B');
      } catch (e) {
        log('write overload resolve: ' + e);
        raf = null;
      }
    }
  }

  var baseNum = ptrToNum(mod.base);
  var readableBytes = 0;
  var holes = [];
  var rangeInfo = [];
  var writtenAny = false;

  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    var relStart = ptrToNum(r.base) - baseNum;
    rangeInfo.push({ offset: relStart, size: r.size, protection: r.protection });
    var readable = r.protection.indexOf('r') >= 0;
    if (!readable) {
      holes.push({ offset: relStart, size: r.size, protection: r.protection });
      continue;
    }
    var pos = relStart;
    var abs = r.base;
    var remaining = r.size;
    while (remaining > 0) {
      var n = Math.min(CHUNK_MOD, remaining);
      var buf = null;
      try {
        buf = Memory.readByteArray(abs, n);
      } catch (e) {
        buf = null;
      }
      if (buf && buf.byteLength === n) {
        readableBytes += n;
        if (raf && writeArr) {
          try {
            raf.seek(pos);
            writeArr.call(raf, Java.array('byte', toSignedArray(buf)));
            writtenAny = true;
          } catch (we) {
            log('writeChunk ' + name + ' @' + pos + ': ' + we);
          }
        }
      } else {
        holes.push({ offset: pos, size: n, protection: r.protection + '+readfailed' });
      }
      abs = abs.add(n);
      pos += n;
      remaining -= n;
    }
  }
  if (raf) {
    try {
      raf.close();
    } catch (e) {}
    raf = null;
  }

  // manifest: holes + per-range info + the /proc/self/maps lines that
  // mention the module (so the offline analysis can cross-check what the
  // linker mapped and which parts only FOLL_FORCE can recover)
  var manifest = {
    module: name,
    tag: t,
    base: String(mod.base),
    size: mod.size,
    file: path,
    written: writtenAny,
    readable_bytes: readableBytes,
    holes: holes,
    ranges: rangeInfo,
    maps: [],
    generated: new Date().toISOString()
  };
  try {
    var lines = readMapsLines();
    for (var li = 0; li < lines.length; li++) {
      if (lines[li].indexOf(name) >= 0) {
        manifest.maps.push(String(lines[li]).replace(/\n$/, ''));
      }
    }
  } catch (e) {}
  if (path) {
    var mpath = path + '.manifest.json';
    var mraf = null;
    try {
      mraf = openRaf(mpath);
      if (mraf) {
        var warr = mraf.write.overload('[B');
        mraf.seek(0);
        warr.call(mraf, Java.array('byte', strToSigned(JSON.stringify(manifest))));
        mraf.close();
        mraf = null;
      }
    } catch (e3) {
      log('manifest write: ' + e3);
      try {
        if (mraf) {
          mraf.close();
        }
      } catch (e4) {}
    }
  }

  return {
    module: name,
    base: String(mod.base),
    size: mod.size,
    readable_bytes: readableBytes,
    holes: holes.length,
    path: path || '(write skipped - no Java)',
    written: writtenAny
  };
}

rpc.exports = {
  dexcensus: function () {
    var res = null;
    try {
      res = dexcensusInner();
    } catch (e) {
      log('dexcensus: ' + e);
      res = { spans: [], when: new Date().toISOString(), error: String(e) };
    }
    try {
      send({
        type: 'dexcensus',
        spans: res.spans.length,
        total_bytes: res.total_probe_readable || 0,
        when: res.when
      });
    } catch (se) {}
    return res;
  },
  dumpmodule: function (name, tag) {
    var t = tag || 'pre';
    var out = null;
    try {
      if (javaOk()) {
        Java.perform(function () {
          try {
            out = dumpModuleInner(name, t);
          } catch (e) {
            out = { error: String(e), module: name };
          }
        });
      } else {
        out = dumpModuleInner(name, t);
      }
    } catch (e) {
      out = { error: String(e), module: name };
    }
    try {
      send({ type: 'redump_module', module: name, tag: t, result: out });
    } catch (se) {}
    return out;
  },
  listmodules: function (filter) {
    var out = [];
    try {
      var mods = Process.enumerateModules();
      var f = (typeof filter === 'string') ? filter : '';
      for (var i = 0; i < mods.length; i++) {
        var m = mods[i];
        if (f && m.name.indexOf(f) < 0) {
          continue;
        }
        out.push({ name: m.name, base: String(m.base), size: m.size, path: m.path });
      }
    } catch (e) {
      log('listmodules: ' + e);
    }
    try {
      send({ type: 'redump_modules', filter: filter || '', count: out.length });
    } catch (se) {}
    return out;
  }
};
