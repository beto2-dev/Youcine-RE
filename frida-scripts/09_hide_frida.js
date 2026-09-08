/*
 * Youcine-RE - 09_hide_frida.js (anti-anti-frida hardening)
 *
 * WHY: run 34171467849 - the spawn-gated process (pid 3480) was SIGKILLed
 * ~1s after resume; ActivityManager restarted the app uninstrumented
 * (pid 3512) and the whole phase-2 capture was lost ("session detached").
 * iJiami's native death ladder detects the frida agent via:
 *   (1) /proc/self/maps -> "/memfd:frida-agent-64.so (deleted)" lines
 *   (2) /proc/net/tcp{,6} -> the listening frida-server socket
 *   (3) /proc/self/task/<tid>/{comm,stat} -> gum-js-loop/gmain/gdbus threads
 *   (4) connect() probes against the frida-server port
 * and then kills itself (kill/raise/abort/exit_group).
 *
 * WHAT (all best-effort, every hook individually try/catch'ed - a failed
 * hook must never crash the packed process):
 *   - open/openat/fopen/fopen64 of sanitized /proc paths return a FILTERED
 *     memfd copy instead of the real file (maps/smaps: frida lines dropped;
 *     net/tcp{,6}: frida port line dropped; status: TracerPid forced to 0;
 *     task/<tid>/comm+stat of frida threads: benign thread name).  The memfd
 *     is labeled "jit-cache" so it looks like a normal Android artifact.
 *   - getdents64 on /proc/self/task drops the frida thread TIDs entirely.
 *   - kill/tgkill/killpg/raise with a self-targeting signal: the signal
 *     argument is zeroed (kill(pid,0) == harmless existence probe).
 *   - abort/exit/_exit replaced with no-op (logged, caller continues).
 *   - libc syscall() with nr in {exit(93), exit_group(94), kill(129),
 *     tkill(130), tgkill(131)}: neutralized the same way.
 *   - connect() to the frida-server port (47890) or classic 27042: returns -1.
 *   - every blocked attempt is reported with a backtrace - the module+offset
 *     of the killer is exactly what we need to neutralize the detector
 *     itself in the next round.
 *
 * ES5 only (duktape runtime, no arrow/let/const/template literals).
 */
'use strict';

var TARGET = 'com.world.youcinemobile';
var FRIDA_PORTS = [47890, 27042];      /* device-side frida-server ports    */
var FRIDA_PORT_HEX = 'bb12';           /* 47890 == 0xBB12 (/proc/net/tcp)   */

/* ------------------------------------------------------------------ utils */
function log(s) { console.log('[hidefrida] ' + s); }

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

function getfn(name, ret, args) {
  var p = Module.findExportByName('libc.so', name);
  if (!p) { return null; }
  return new NativeFunction(p, ret, args);
}

var M = {
  read: null, write: null, lseek: null, close: null, fileno: null,
  fdopen: null, memfd_create: null, syscall: null, opendir: null,
  readdir: null, closedir: null, getpid: null
};

function libc_init() {
  M.read = getfn('read', 'long', ['int', 'pointer', 'long']);
  M.write = getfn('write', 'int', ['int', 'pointer', 'long']);
  M.lseek = getfn('lseek', 'long', ['int', 'long', 'int']);
  M.close = getfn('close', 'int', ['int']);
  M.fileno = getfn('fileno', 'int', ['pointer']);
  M.fdopen = getfn('fdopen', 'pointer', ['int', 'pointer']);
  M.getpid = getfn('getpid', 'int', []);
  M.opendir = getfn('opendir', 'pointer', ['pointer']);
  M.readdir = getfn('readdir', 'pointer', ['pointer']);
  M.closedir = getfn('closedir', 'int', ['pointer']);
  var m = Module.findExportByName('libc.so', 'memfd_create');
  if (m) {
    M.memfd_create = new NativeFunction(m, 'int', ['pointer', 'int']);
  } else {
    /* arm64: __NR_memfd_create == 279 */
    M.syscall = getfn('syscall', 'long', ['long', 'long', 'long', 'long']);
  }
}

function my_pid() {
  try { return M.getpid(); } catch (e) { return -1; }
}

function read_all_fd(fd) {
  /* returns the full (ASCII) content of fd as a JS string, or '' */
  try {
    M.lseek(fd, 0, 0);
    var buf = Memory.alloc(65536);
    var out = [];
    for (;;) {
      var n = M.read(fd, buf, 65536);
      if (n <= 0) { break; }
      out.push(Memory.readUtf8String(buf, n.toInt32 ? n.toInt32() : n));
    }
    return out.join('');
  } catch (e) {
    return '';
  }
}

function make_memfd(content) {
  /* memfd labeled "jit-cache"; returns the fd rewound to 0, or -1 */
  try {
    var name = Memory.allocAnsiString('jit-cache');
    var fd;
    if (M.memfd_create) {
      fd = M.memfd_create(name, 0);
    } else {
      fd = M.syscall(279, name, 0);
      if (fd > 0x7fffffff) { fd = -1; }  /* sign-fix the long return */
    }
    if (fd < 0) { return -1; }
    var w = Memory.allocUtf8String(content);
    var off = 0, CH = 65536;
    while (off < content.length) {
      var take = Math.min(CH, content.length - off);
      M.write(fd, w.add(off), take);
      off += take;
    }
    M.lseek(fd, 0, 0);
    return fd;
  } catch (e) {
    log('make_memfd failed: ' + e);
    return -1;
  }
}

/* --------------------------------------------------------- /proc filters */
var FRIDA_TIDS = {};    /* tid -> fake name, filled at install time */

function looks_frida_thread(name) {
  if (!name) { return false; }
  var n = name.toLowerCase();
  return n.indexOf('gum-') === 0 || n.indexOf('gmain') === 0 ||
         n.indexOf('gdbus') === 0 || n.indexOf('pool-frida') === 0 ||
         n.indexOf('frida') !== -1;
}

function scan_frida_threads() {
  try {
    var dp = Memory.allocAnsiString('/proc/self/task');
    var dir = M.opendir(dp);
    if (dir.isNull()) { return; }
    for (;;) {
      var de = M.readdir(dir);
      if (de.isNull()) { break; }
      /* struct dirent: d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name@19 */
      var name = Memory.readCString(de.add(19));
      var tid = parseInt(name, 10);
      if (!isNaN(tid) && tid > 0) {
        try {
          var f = new File('/proc/self/task/' + tid + '/comm', 'r');
          var comm = (f.readLine() || '').replace(/\u0000/g, '').replace(/\n/g, '');
          f.close();
          if (looks_frida_thread(comm)) {
            FRIDA_TIDS[tid] = 'Thread-' + (tid % 100000);
          }
        } catch (e2) { /* unreadable comm - skip */ }
      }
    }
    M.closedir(dir);
    var n = 0, k;
    for (k in FRIDA_TIDS) { if (FRIDA_TIDS.hasOwnProperty(k)) { n++; } }
    if (n > 0) { log('hiding ' + n + ' frida thread(s): ' +
                     (function () { var a = [], x; for (x in FRIDA_TIDS) { if (FRIDA_TIDS.hasOwnProperty(x)) { a.push(x + '(' + FRIDA_TIDS[x] + ')'); } } return a.join(' '); })()); }
  } catch (e) {
    log('thread scan failed: ' + e);
  }
}

function filt_maps(s) {
  var lines = s.split('\n'), out = [], i, L;
  for (i = 0; i < lines.length; i++) {
    L = lines[i];
    var low = L.toLowerCase();
    if (low.indexOf('frida') !== -1 || low.indexOf('gadget') !== -1 ||
        low.indexOf('linjector') !== -1 || low.indexOf('gum-js') !== -1) {
      continue;                       /* drop the line entirely */
    }
    out.push(L);
  }
  return out.join('\n');
}

function filt_nettcp(s) {
  var lines = s.split('\n'), out = [], i, L;
  for (i = 0; i < lines.length; i++) {
    L = lines[i];
    var low = L.toLowerCase();
    if (low.indexOf(':' + FRIDA_PORT_HEX + ' ') !== -1) {
      continue;                       /* the frida-server listener row */
    }
    out.push(L);
  }
  return out.join('\n');
}

function filt_status(s) {
  try {
    return s.replace(/TracerPid:\s*\d+/i, 'TracerPid:\t0');
  } catch (e) {
    return s;
  }
}

function filt_comm(s, fake) {
  return fake + '\n';
}

function filt_stat(s, fake) {
  try {
    return s.replace(/^\d+ \([^\x00\n]*\)/, s.split(' ')[0] + ' (' + fake + ')');
  } catch (e) {
    return s;
  }
}

/* kind for a /proc path: 0 none, 1 maps, 2 nettcp, 3 status, 4 frida comm,
 * 5 frida stat */
function proc_kind(path) {
  if (!path || path.indexOf('/proc') !== 0) { return 0; }
  var pid = my_pid();
  var self = (path.indexOf('/proc/self/') === 0) ||
             (pid > 0 && path.indexOf('/proc/' + pid + '/') === 0);
  var rest = path.replace(/^\/proc\/(self|\d+)\//, '');
  if (!self) {
    if (path === '/proc/net/tcp' || path === '/proc/net/tcp6') { return 2; }
    return 0;
  }
  if (rest === 'maps' || rest === 'smaps' || rest.indexOf('smaps') === 0) { return 1; }
  if (path === '/proc/net/tcp' || path === '/proc/net/tcp6') { return 2; }
  if (rest === 'net/tcp' || rest === 'net/tcp6') { return 2; }
  if (rest === 'status') { return 3; }
  var m = /^task\/(\d+)\/(comm|stat)$/.exec(rest);
  if (m) {
    var tid = parseInt(m[1], 10);
    if (FRIDA_TIDS.hasOwnProperty(tid)) {
      return m[2] === 'comm' ? 4 : 5;
    }
  }
  return 0;
}

function sanitize(path, content) {
  var k = proc_kind(path);
  if (k === 0) { return content; }
  if (k === 1) { return filt_maps(content); }
  if (k === 2) { return filt_nettcp(content); }
  if (k === 3) { return filt_status(content); }
  if (k === 4) { return filt_comm(content, FRIDA_TIDS[tid_of(path)]); }
  if (k === 5) { return filt_stat(content, FRIDA_TIDS[tid_of(path)]); }
  return content;
}

function tid_of(path) {
  var m = /task\/(\d+)\//.exec(path);
  return m ? parseInt(m[1], 10) : 0;
}

function wants_sanitize(path) {
  return proc_kind(path) !== 0;
}

/* -------------------------------------------------------- open/openat etc */
function hook_open_like(name, pathArgIndex) {
  try {
    var p = Module.findExportByName('libc.so', name);
    if (!p) { return; }
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.path = '';
        try {
          this.path = Memory.readCString(args[pathArgIndex]);
        } catch (e) { /* ignore */ }
        this.want = wants_sanitize(this.path);
        if (this.path === '/proc/self/task' || this.path === '/proc/self/task/') {
          this.taskdir = true;
        }
      },
      onLeave: function (retval) {
        try {
          if (this.taskdir && retval.toInt32() > 0) {
            TASK_FDS[retval.toInt32()] = true;   /* for getdents64 */
          }
          if (!this.want) { return; }
          var fd = retval.toInt32();
          if (fd <= 0) { return; }
          var content = read_all_fd(fd);
          if (!content) { return; }
          var clean = sanitize(this.path, content);
          if (clean === content) { return; }
          var mfd = make_memfd(clean);
          if (mfd < 0) { return; }
          M.close(fd);
          retval.replace(mfd);
          send({ type: 'hidefrida', what: 'proc', path: this.path });
        } catch (e) { /* never crash the app */ }
      }
    });
    log('hooked ' + name);
  } catch (e) {
    log('hook ' + name + ' failed: ' + e);
  }
}

function hook_fopen(name) {
  try {
    var p = Module.findExportByName('libc.so', name);
    if (!p) { return; }
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.path = '';
        this.mode = 'r';
        try {
          this.path = Memory.readCString(args[0]);
          this.mode = Memory.readCString(args[1]) || 'r';
        } catch (e) { /* ignore */ }
        this.want = wants_sanitize(this.path);
      },
      onLeave: function (retval) {
        try {
          if (!this.want || retval.isNull()) { return; }
          var fd = M.fileno(retval);
          if (fd <= 0) { return; }
          var content = read_all_fd(fd);
          if (!content) { return; }
          var clean = sanitize(this.path, content);
          if (clean === content) { return; }
          var mfd = make_memfd(clean);
          if (mfd < 0) { return; }
          var mode = Memory.allocAnsiString(this.mode.indexOf('w') !== -1 ? 'w+' : 'r');
          var nf = M.fdopen(mfd, mode);
          if (nf.isNull()) { return; }
          /* close the original stream (safe: fclose never re-enters fopen) */
          var fclose = getfn('fclose', 'int', ['pointer']);
          if (fclose) { fclose(retval); }
          retval.replace(nf);
          send({ type: 'hidefrida', what: 'proc', path: this.path });
        } catch (e) { /* never crash the app */ }
      }
    });
    log('hooked ' + name);
  } catch (e) {
    log('hook ' + name + ' failed: ' + e);
  }
}

/* ----------------------------------------------------------- getdents64 */
var TASK_FDS = {};   /* fd -> true when opened on /proc/self/task */

function hook_getdents64() {
  try {
    var p = Module.findExportByName('libc.so', 'getdents64');
    if (!p) { return; }
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
      },
      onLeave: function (retval) {
        try {
          if (!TASK_FDS[this.fd]) { return; }
          var total = retval.toInt32();
          if (total <= 0) { return; }
          var out = [];
          var off = 0;
          while (off < total) {
            var e = this.buf.add(off);
            var reclen = Memory.readU16(e.add(16)) & 0xffff;
            if (reclen === 0) { break; }
            var name = Memory.readCString(e.add(19));
            var tid = parseInt(name, 10);
            if (isNaN(tid) || !FRIDA_TIDS.hasOwnProperty(tid)) {
              var bytes = Memory.readByteArray(e, reclen);
              out.push(bytes);
            }
            off += reclen;
          }
          var w = 0, i;
          for (i = 0; i < out.length; i++) {
            Memory.writeByteArray(this.buf.add(w), out[i]);
            w += out[i].byteLength;
          }
          retval.replace(w);
        } catch (e) { /* never crash the app */ }
      }
    });
    log('hooked getdents64');
  } catch (e) {
    log('hook getdents64 failed: ' + e);
  }
}

/* ------------------------------------------------------- death-ladder block */
function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, 8)
      .map(function (a) {
        var d = DebugSymbol.fromAddress(a);
        return (d.moduleName || '?') + '!' + (d.name || d.address.toString(16));
      }).join(' <- ');
  } catch (e) {
    return 'no-bt';
  }
}

function report_kill(fn, detail, ctx) {
  var line = 'BLOCKED ' + fn + ' ' + detail + ' @ ' + bt(ctx);
  log(line);
  send({ type: 'kill_block', fn: fn, detail: detail, bt: bt(ctx) });
}

function hook_kill_family() {
  /* kill(pid, sig): zero the signal when self-targeted */
  try {
    var p = Module.findExportByName('libc.so', 'kill');
    if (p) {
      Interceptor.attach(p, {
        onEnter: function (args) {
          try {
            var pid = args[0].toInt32();
            var sig = args[1].toInt32();
            var me = my_pid();
            if (sig !== 0 && (pid === me || pid === 0 || pid === -me)) {
              report_kill('kill', 'pid=' + pid + ' sig=' + sig, this.context);
              args[1] = ptr(0);
            }
          } catch (e) { /* ignore */ }
        }
      });
      log('hooked kill');
    }
  } catch (e) { log('hook kill failed: ' + e); }

  /* tgkill(tgid, tid, sig) */
  try {
    var p2 = Module.findExportByName('libc.so', 'tgkill');
    if (p2) {
      Interceptor.attach(p2, {
        onEnter: function (args) {
          try {
            var tgid = args[0].toInt32();
            var sig = args[2].toInt32();
            if (sig !== 0 && tgid === my_pid()) {
              report_kill('tgkill', 'tgid=' + tgid + ' tid=' +
                          args[1].toInt32() + ' sig=' + sig, this.context);
              args[2] = ptr(0);
            }
          } catch (e) { /* ignore */ }
        }
      });
      log('hooked tgkill');
    }
  } catch (e) { log('hook tgkill failed: ' + e); }

  /* raise(sig) */
  try {
    var p3 = Module.findExportByName('libc.so', 'raise');
    if (p3) {
      Interceptor.attach(p3, {
        onEnter: function (args) {
          try {
            var sig = args[0].toInt32();
            if (sig !== 0) {
              report_kill('raise', 'sig=' + sig, this.context);
              args[0] = ptr(0);
            }
          } catch (e) { /* ignore */ }
        }
      });
      log('hooked raise');
    }
  } catch (e) { log('hook raise failed: ' + e); }

  /* abort/exit/_exit: no-op (the caller keeps running) */
  var EXITS = { abort: [], exit: ['int'], _exit: ['int'] };
  ['abort', 'exit', '_exit'].forEach(function (fn) {
    try {
      var q = Module.findExportByName('libc.so', fn);
      if (!q) { return; }
      Interceptor.replace(q, new NativeCallback(
        function (code) {
          report_kill(fn, 'called (code=' + code + ')', null);
          return 0;
        }, 'int', EXITS[fn]));
      log('hooked ' + fn + ' (no-op)');
    } catch (e) {
      log('hook ' + fn + ' failed: ' + e);
    }
  });

  /* raw syscall() with a death-ladder number (arm64) */
  try {
    var p4 = Module.findExportByName('libc.so', 'syscall');
    if (p4) {
      var DEATH = { 93: 'exit', 94: 'exit_group', 129: 'kill',
                    130: 'tkill', 131: 'tgkill' };
      Interceptor.attach(p4, {
        onEnter: function (args) {
          try {
            var nr = args[0].toInt32();
            if (!DEATH.hasOwnProperty(nr)) { return; }
            report_kill('syscall', DEATH[nr] + '(' +
                        args[1].toInt32() + ',' + args[2].toInt32() + ')',
                        this.context);
            if (nr === 129 || nr === 130 || nr === 131) {
              args[2] = ptr(0);            /* the signal argument */
            } else {
              args[0] = ptr(172);          /* exit/exit_group -> getpid */
            }
          } catch (e) { /* ignore */ }
        }
      });
      log('hooked syscall (death numbers)');
    }
  } catch (e) { log('hook syscall failed: ' + e); }
}

/* ------------------------------------------------------- connect() block */
function hook_connect() {
  try {
    var p = Module.findExportByName('libc.so', 'connect');
    if (!p) { return; }
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.block = false;
        try {
          var sa = args[1];
          if (sa.isNull()) { return; }
          var fam = Memory.readU16(sa);
          if (fam !== 2 && fam !== 10) { return; }    /* AF_INET / AF_INET6 */
          var port = (Memory.readU8(sa.add(2)) << 8) | Memory.readU8(sa.add(3));
          var i;
          for (i = 0; i < FRIDA_PORTS.length; i++) {
            if (port === FRIDA_PORTS[i]) {
              this.block = true;
              report_kill('connect', 'port=' + port + ' (frida probe)',
                          this.context);
              return;
            }
          }
        } catch (e) { /* ignore */ }
      },
      onLeave: function (retval) {
        try {
          if (this.block) { retval.replace(-1); }
        } catch (e) { /* ignore */ }
      }
    });
    log('hooked connect (frida ports)');
  } catch (e) {
    log('hook connect failed: ' + e);
  }
}

/* ------------------------------------------------------------------ main */
function hook() {
  if (cmdline().indexOf(TARGET) !== 0) {
    return;
  }
  libc_init();
  if (!M.read || !M.write || !M.lseek) {
    log('libc essentials missing - aborting (no hooks)');
    return;
  }
  log('active in ' + TARGET + ' pid=' + my_pid());
  scan_frida_threads();
  hook_open_like('open', 0);
  hook_open_like('openat', 1);
  hook_fopen('fopen');
  try { hook_fopen('fopen64'); } catch (e) { /* optional export */ }
  hook_getdents64();
  hook_kill_family();
  hook_connect();
  /* re-scan threads once after 5s: the agent may spawn gmain/gdbus lazily */
  setTimeout(function () {
    try { scan_frida_threads(); } catch (e) { /* ignore */ }
  }, 5000);
  log('installed (maps/tcp/threads sanitized, death ladder blocked)');
}

setImmediate(function () {
  try {
    hook();
  } catch (e) {
    log('init failed: ' + e);
  }
});
