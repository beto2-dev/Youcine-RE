#!/usr/bin/env python3
"""Stage-2 emulator for the UNPACKED iJiami SecShell libexec.so (x86).

After emulate_unpack.py has unpacked the hidden region, the library is a
normal ELF image whose imports are called through 216 JMP_SLOT GOT entries.
This script:
  - loads the unpacked image (RX 0x0-0xe1c00 + RW from original file),
  - pre-resolves every GOT slot to a unique trampoline (0x60000000+k*16),
  - emulates the 63 .init_array functions and (optionally) JNI_OnLoad,
  - implements/emulates the interesting imports in Python and LOGS them:
      __system_property_get(name, buf)  -> the anti-debug gate
      AAssetManager_open(mgr, name)     -> the ijiami.dat payload read
      ptrace / fork / kill / pthread_create / dlopen / dlsym / open / read ...
  - serves assets/ijiami.dat bytes for AAsset_read so decryption can run.

Usage: emulate_stage2.py <unpacked_image.bin> <orig_libexec.so> <mode> [prop=value ...]
  mode: init | jni | all
"""
import sys, os, struct, collections
from unicorn import *
from unicorn.x86_const import *

IMG = sys.argv[1]
ORIG = sys.argv[2]
MODE = "gate"
GATE_FN = 0x61560
PROPS = {}
for a in sys.argv[4:]:
    if '=' in a:
        k, v = a.split('=', 1)
        PROPS[k] = v

img = bytearray(open(IMG, 'rb').read())
orig = open(ORIG, 'rb').read()
APK = "/home/z/youcine-re/apk/ycMob_1.17.6_ycsite.apk"
IJM = open("/tmp/ijm/ijiami.dat", 'rb').read() if os.path.exists("/tmp/ijm/ijiami.dat") else b""

# ---- parse ELF dynamic info from ORIGINAL file ----
phoff = struct.unpack('<I', orig[28:32])[0]
phentsize, phnum = struct.unpack('<HH', orig[42:46])
loads = []
dyn_off = dyn_sz = None
for i in range(phnum):
    p = orig[phoff+32*i: phoff+32*(i+1)]
    t, off, va, pa, fsz, msz, fl, al = struct.unpack('<8I', p)
    if t == 1: loads.append((off, va, fsz, msz, fl))
    if t == 2: dyn_off, dyn_sz = off, fsz
dyn = {}
p = dyn_off
while p < dyn_off + dyn_sz:
    tag, val = struct.unpack('<II', orig[p:p+8])
    dyn[tag] = val
    p += 8
    if tag == 0: break
DT = {1:'NEEDED',2:'PLTRELSZ',5:'STRTAB',6:'SYMTAB',10:'STRSZ',11:'SYMENT',17:'JMPREL',2:'PLTRELSZ',20:'PLTREL',23:'JMPREL',2:'x'}
symtab, strtab, strsz = dyn[6], dyn[5], dyn[10]
jmprel, pltrelsz = dyn[23], dyn[2]
# true symbol count via DT_HASH (hash at dyn[4])
nb, nchain = struct.unpack('<II', orig[dyn[4]:dyn[4]+8])
def symname(j):
    no = struct.unpack('<I', orig[symtab+16*j:symtab+16*j+4])[0]
    if no >= strsz: return f'<oob:{j}>'
    end = orig[strtab+no:].find(b'\x00')
    return orig[strtab+no:strtab+no+end].decode('latin1')
# GOT slots from JMPREL (216 entries)
slots = []          # (got_addr, symname)
for k in range(pltrelsz // 8):
    off, info = struct.unpack('<II', orig[jmprel+8*k:jmprel+8*k+8])
    slots.append((off, symname(info >> 8)))
print(f"GOT slots: {len(slots)}, first: {slots[:3]}")

uc = Uc(UC_ARCH_X86, UC_MODE_32)
PAGE = 0x1000
def align_up(x): return (x + PAGE-1) & ~(PAGE-1)

# map image + RW
RX_END = 0xe1c00
uc.mem_map(0, align_up(len(img)), UC_PROT_ALL)
uc.mem_write(0, bytes(img))
RW_VA, RW_FSZ, RW_MEM = 0xe5c00, 0x12144, 0x142b8
uc.mem_write(RW_VA, orig[0x75c00:0x75c00+RW_FSZ])
BSS_START = align_up(max(len(img), 0xe7928))
try:
    uc.mem_map(BSS_START, 0x100000, UC_PROT_ALL)  # .bss slack
except UcError:
    pass

STACK = 0x7f000000
uc.mem_map(0x6a100000, 0x14f00000, UC_PROT_ALL)  # stack 0x6a100000-0x7f000000
TRAMP = 0x60000000
uc.mem_map(TRAMP, 0x100000, UC_PROT_ALL)
HEAP = 0x62000000
uc.mem_map(HEAP, 0x8000000, UC_PROT_ALL)   # 128MB heap arena
heap_cur = [HEAP]
AASSET = 0x56000000
uc.mem_map(AASSET, 0x1000, UC_PROT_ALL)

# pre-resolve GOT slots to trampolines
tramp_for_slot = {}
for k, (got, name) in enumerate(slots):
    t = TRAMP + 16*k
    tramp_for_slot[t] = (k, name, got)
    uc.mem_write(got, struct.pack('<I', t))

log = []
insn = [0]
cur_fn = ['<none>']

def logi(msg):
    log.append(f"[{cur_fn[0]}] {msg}")

def rd(a, n): return bytes(uc.mem_read(a, n))
def wr(a, b): uc.mem_write(a, b)
def cstr(a, maxn=512):
    out = b''
    while len(out) < maxn:
        c = rd(a+len(out), 1)
        if c == b'\x00': break
        out += c
    return out.decode('latin1')

def arg(i):   # cdecl arg i at [esp+4+4i]
    esp = uc.reg_read(UC_X86_REG_ESP)
    return struct.unpack('<I', rd(esp+4+4*i, 4))[0]

def ret(val):
    esp = uc.reg_read(UC_X86_REG_ESP)
    eip = struct.unpack('<I', rd(esp, 4))[0]
    uc.reg_write(UC_X86_REG_ESP, esp+4)
    uc.reg_write(UC_X86_REG_EAX, val & 0xffffffff)
    uc.reg_write(UC_X86_REG_EIP, eip)

HEAP2 = 0x57000000
uc.mem_map(HEAP2, 0x100000, UC_PROT_ALL)
heap2_cur = [HEAP2]
DLSYM_FAKE = 0x58000000
uc.mem_map(DLSYM_FAKE, 0x1000, UC_PROT_ALL)
uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: (
    logi(f"*** dlsym'd pthread_create called: start=0x{arg(2):x} arg=0x{arg(3):x} ***"), ret(0)
), begin=DLSYM_FAKE, end=DLSYM_FAKE+0x10)

def h_malloc(n): 
    p = heap_cur[0]; heap_cur[0] += (n + 15) & ~15
    return p
FILECTR = [0x61000000]
FILES = {}
# ---- environment simulation (IJM_ENV=clean|emulator|rooted|...) ----
import os as _os
ENVKIND = _os.environ.get('IJM_ENV', 'clean')
FSIM = {}
ACCESS_OK = set()
# every real device has these (TracerPid 0 = untraced)
FSIM.update({
  '/proc/self/status': _os.environ.get('IJM_STATUS',
     'Name:\tfoo\nState:\tS (sleeping)\nTgid:\t4242\nPid:\t4242\nPPid:\t123\nTracerPid:\t%s\nUid:\t10086\t10086\t10086\t10086\nGid:\t10086\t10086\t10086\t10086\n' % _os.environ.get('IJM_TRACERPID', '0')).encode(),
  '/proc/self/wchan': b'sys_epoll\n',
  '/proc/self/maps': b'',
})
if ENVKIND == 'emulator':
    FSIM.update({
      '/dev/qemu_pipe': b'',
      '/dev/socket/qemud': b'',
      '/proc/tty/drivers': b'goldfish_pipe /dev/ttyGF0 9 57 -1\n',
      '/proc/self/status': b'Name:\tfoo\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\nPPid:\t123\nTracerPid:\t0\nUid:\t10086\t10086\t10086\t10086\nGid:\t10086\t10086\t10086\t10086\n',
      '/proc/self/wchan': b'sys_epoll\n',
    })
elif ENVKIND == 'emulator_noqemuprops':
    FSIM.update({
      '/dev/qemu_pipe': b'',
      '/dev/socket/qemud': b'',
      '/proc/tty/drivers': b'goldfish_pipe /dev/ttyGF0 9 57 -1\n',
      '/proc/self/status': b'Name:\tfoo\nState:\tS (sleeping)\nTracerPid:\t0\n',
    })
elif ENVKIND == 'rooted':
    pass
for _p in ('/system/bin/su','/system/xbin/su','/system/sbin/su','/sbin/su','/vendor/bin/su','/su/bin/su'):
    if ENVKIND in ('emulator','rooted'):
        FSIM.setdefault(_p, b''); ACCESS_OK.add(_p)
ACCESS_OK |= set(FSIM)
FDCTR = [0x70000000]
FDS = {}
print(f"[env] IJM_ENV={ENVKIND} files={sorted(FSIM)}")
def h_fopen(path, mode):
    p = cstr(path)
    logi(f"fopen({p!r}, {mode})")
    f = FILECTR[0]; FILECTR[0] += 0x100
    FILES[f] = {'path': p, 'pos': 0, 'data': FSIM.get(p, b'')}
    return f

def sys_property_get(name, buf):
    p = cstr(name)
    v = PROPS.get(p, '')
    logi(f"__system_property_get({p!r}) -> {v!r}")
    if v:
        wr(buf, v.encode() + b'\x00')
        return len(v)
    return 0

ASSETS = {}
def aasset_open(mgr, name, mode):
    p = cstr(name)
    logi(f"AAssetManager_open({p!r}, mode={mode})")
    if p.endswith('ijiami.dat'):
        ASSETS[AASSET] = {'data': IJM, 'pos': 0, 'name': p}
        return AASSET
    return 0

import io
def impl(k, name):
    if name == 'malloc': return lambda: ret(h_malloc(arg(0)))
    if name == 'calloc': return lambda: (lambda n,s: ret(h_malloc(n*s)))(arg(0), arg(1))
    if name == 'realloc': return lambda: ret(h_malloc(arg(1)))
    if name == 'free': return lambda: ret(0)
    if name == '__system_property_get': return lambda: sys_property_get(arg(0), arg(1)) or ret(sys_property_get.__out__ if False else 0)
    if name == 'fopen': return lambda: h_fopen(arg(0), arg(1)) or ret(h_fopen.__out__ if False else 0)
    return None

def tramp_dispatch(uc, addr, size, ud):
    if not (TRAMP <= addr < TRAMP + 0x100000): return
    k, name, got = tramp_for_slot[addr]
    if name == 'malloc': ret(h_malloc(arg(0)))
    elif name in ('calloc',): 
        n, s = arg(0), arg(1); ret(h_malloc(n*s))
    elif name == 'realloc':
        old, n = arg(0), arg(1); ret(h_malloc(n))
    elif name in ('free', 'pthread_mutex_init', 'pthread_mutex_destroy', 'pthread_key_delete'):
        ret(0)
    elif name == 'pthread_mutex_lock' or name == 'pthread_mutex_unlock':
        ret(0)
    elif name == 'pthread_key_create': ret(0)
    elif name == 'pthread_getspecific': ret(0)
    elif name == 'pthread_setspecific': ret(0)
    elif name == '__system_property_get':
        r = sys_property_get(arg(0), arg(1)); ret(r)
    elif name == 'AAssetManager_fromJava':
        logi(f"AAssetManager_fromJava(env=0x{arg(0):x}, am=0x{arg(1):x})")
        ret(0x61000000)
    elif name == 'AAssetManager_open':
        r = aasset_open(arg(0), arg(1), arg(2)); ret(r)
    elif name == 'AAsset_getLength64':
        a = arg(0)
        if a in ASSETS: ret(len(ASSETS[a]['data']))
        else: ret(0)
    elif name == 'AAsset_read':
        a, buf, n = arg(0), arg(1), arg(2)
        if a in ASSETS:
            d = ASSETS[a]['data']; pos = ASSETS[a]['pos']
            chunk = d[pos:pos+n]; ASSETS[a]['pos'] += len(chunk)
            wr(buf, chunk)
            logi(f"AAsset_read({ASSETS[a]['name']!r}, n={n}) -> {len(chunk)} bytes @{pos}")
            ret(len(chunk))
        else: ret(0)
    elif name == 'AAsset_close':
        logi(f"AAsset_close()"); a = arg(0); ASSETS.pop(a, None); ret(0)
    elif name == 'fopen':
        f = h_fopen(arg(0), arg(1)); ret(f)
    elif name == 'fclose': ret(0)
    elif name in ('fgets',):
        buf, size, fp = arg(0), arg(1), arg(2)
        d = FILES.get(fp, {}).get('data', b'')
        pos = FILES.get(fp, {}).get('pos', 0)
        if pos < len(d):
            nl = d.find(b'\n', pos)
            line = d[pos:nl+1 if nl>=0 else len(d)][:size-1]
            FILES[fp]['pos'] += len(line)
            wr(buf, line + b'\x00')
            logi(f"fgets(fp={FILES[fp]['path']!r}) -> {line!r}")
            ret(buf)
        else:
            logi(f"fgets(fp={FILES.get(fp,{}).get('path','?')!r}) -> NULL"); ret(0)
    elif name == 'fread':
        buf, sz, n, fp = arg(0), arg(1), arg(2), arg(3)
        d = FILES.get(fp, {})
        data = d.get('data', b''); pos = d.get('pos', 0)
        chunk = data[pos:pos+sz*n]
        if fp in FILES: FILES[fp]['pos'] += len(chunk)
        wr(buf, chunk); logi(f"fread(fp={d.get('path','?')!r}, n={sz*n}) -> {chunk[:64]!r}"); ret(len(chunk)//sz if sz else 0)
    elif name in ('__android_log_write',):
        logi(f"log_write: {cstr(arg(2))!r} {cstr(arg(3))!r}"); ret(0)
    elif name == 'ptrace':
        logi(f"ptrace(req={arg(0)}, pid={arg(1)}) -> 0"); ret(0)
    elif name == 'strdup':
        p = cstr(arg(0))
        b = heap2_cur[0]; heap2_cur[0] += len(p)+1
        wr(b, p.encode('latin1')+b'\x00')
        logi(f"strdup({p!r}) -> 0x{b:x}"); ret(b)
    elif name == 'memcpy' or name == 'memmove':
        dst, src, n = arg(0), arg(1), arg(2)
        wr(dst, bytes(rd(src, n))); ret(dst)
    elif name == 'strlen':
        ret(len(cstr(arg(0))))
    elif name == 'getenv':
        logi(f"getenv({cstr(arg(0))!r})"); ret(0)
    elif name == 'strchr':
        s = cstr(arg(0)); ch = arg(1) & 0xff
        idx = s.find(chr(ch))
        ret(arg(0)+idx if idx >= 0 else 0)
    elif name == 'atoi':
        s = cstr(arg(0)).strip()
        try: v = int(s.split()[0].rstrip('a-zA-Z'))
        except Exception: v = 0
        ret(v & 0xffffffff)
    elif name == 'strncmp':
        a = rd(arg(0), arg(2)+1); b = rd(arg(1), arg(2)+1)
        n = arg(2)
        ret(0 if a[:n] == b[:n] else 1)
    elif name == 'strcmp':
        a = cstr(arg(0)); b = cstr(arg(1))
        ret(0 if a == b else 1)
    elif name == 'fork':
        logi("fork() -> 12345 (parent)"); ret(12345)
    elif name == 'kill':
        logi(f"kill(pid={arg(0)}, sig={arg(1)})"); ret(0)
    elif name == 'prctl': logi(f"prctl({arg(0)})"); ret(0)
    elif name == 'pthread_create':
        logi(f"pthread_create(start=0x{arg(2):x}, arg=0x{arg(3):x}) -- SKIPPED"); ret(0)
    elif name == 'dlopen':
        logi(f"dlopen({cstr(arg(0))!r}) -> fake"); ret(0x64000000)
    elif name == 'dlsym':
        sname = cstr(arg(1)) if arg(1) else '?'
        if _os.environ.get('IJM_DLSYM') == 'ok':
            logi(f"dlsym(handle=0x{arg(0):x}, {sname!r}) -> 0x{DLSYM_FAKE:x} (fake ok)"); ret(DLSYM_FAKE)
        else:
            logi(f"dlsym(handle=0x{arg(0):x}, {sname!r}) -> 0"); ret(0)
    elif name == 'dlclose': ret(0)
    elif name == 'open' or name == '__open_2':
        p = cstr(arg(0))
        if p in FSIM:
            fd = FDCTR[0]; FDCTR[0] += 0x100
            FDS[fd] = {'path': p, 'pos': 0, 'data': FSIM[p]}
            logi(f"open({p!r}) -> fd 0x{fd:x}"); ret(fd)
        else:
            logi(f"open({p!r}, flags={arg(1)}) -> -1"); ret(0xffffffff)
    elif name == 'read':
        fd, buf, n = arg(0), arg(1), arg(2)
        d = FDS.get(fd)
        if d:
            chunk = d['data'][d['pos']:d['pos']+n]; d['pos'] += len(chunk)
            wr(buf, chunk); logi(f"read({d['path']!r}, n={n}) -> {chunk[:64]!r}"); ret(len(chunk))
        else:
            logi(f"read(fd=0x{fd:x}, n={n}) -> 0"); ret(0)
    elif name == 'close': ret(0)
    elif name == 'lseek64' or name == 'lseek': ret(0)
    elif name == 'stat' or name == 'lstat' or name == 'fstat': ret(0xffffffff)
    elif name == 'access':
        p = cstr(arg(0))
        if p in ACCESS_OK:
            logi(f"access({p!r}) -> 0 (EXISTS)"); ret(0)
        else:
            logi(f"access({p!r}, {arg(1)}) -> -1"); ret(0xffffffff)
    elif name == 'opendir': logi(f"opendir({cstr(arg(0))!r}) -> NULL"); ret(0)
    elif name == 'readdir': ret(0)
    elif name == 'readlink': logi(f"readlink({cstr(arg(0))!r})"); ret(0)
    elif name == 'syscall':
        logi(f"syscall({arg(0)}, {arg(1)}, {arg(2)})")
        ret(0)
    elif name == 'getppid': logi("getppid()"); ret(4242)
    elif name == 'getpid': logi("getpid()"); ret(4242)
    elif name == 'gettid': ret(4242)
    elif name == 'regcomp': ret(0)
    elif name == 'regexec': ret(1)  # no match
    elif name == 'sleep' or name == 'usleep': ret(0)
    elif name == 'time': ret(1700000000)
    elif name == 'siglongjmp' or name == 'sigsetjmp': ret(0)
    else:
        logi(f"UNIMPL import called: {name}(0x{arg(0):x}, 0x{arg(1):x}) -> 0")
        ret(0)

hist = collections.Counter()
def code_hook(uc, addr, size, ud):
    insn[0] += 1
    if insn[0] % 4 == 0:
        hist[addr] += 1
    if insn[0] > 60_000_000:
        log.append("instruction cap"); uc.emu_stop()

def mem_bad(uc, access, address, size, value, ud):
    eip = uc.reg_read(UC_X86_REG_EIP)
    log.append(f"INVALID MEM access={access} addr=0x{address:x} size={size} eip=0x{eip:x} fn={cur_fn[0]}")
    return False

uc.hook_add(UC_HOOK_CODE, tramp_dispatch, begin=TRAMP, end=TRAMP+0x100000)
uc.hook_add(UC_HOOK_CODE, code_hook)
uc.hook_add(UC_HOOK_MEM_INVALID, mem_bad)

def intr_hook(uc, intno, ud):
    if intno != 0x80: return
    eax = uc.reg_read(UC_X86_REG_EAX)
    ebx = uc.reg_read(UC_X86_REG_EBX)
    ecx = uc.reg_read(UC_X86_REG_ECX)
    edx = uc.reg_read(UC_X86_REG_EDX)
    eip = uc.reg_read(UC_X86_REG_EIP)
    if eax == 5:  # open(path, flags, mode) -- serve FSIM files
        p = cstr(ebx)
        if p in FSIM:
            fd = FDCTR[0]; FDCTR[0] += 0x100
            FDS[fd] = {'path': p, 'pos': 0, 'data': FSIM[p]}
            logi(f"int80 open({p!r}) -> fd 0x{fd:x}")
            uc.reg_write(UC_X86_REG_EAX, fd)
        elif p in ('/proc/self/maps', '/proc/%d/maps' % 4242):
            fd = FDCTR[0]; FDCTR[0] += 0x100
            FDS[fd] = {'path': p, 'pos': 0, 'data': FSIM.get(p, b'')}
            logi(f"int80 open({p!r}) -> fd 0x{fd:x} (empty)")
            uc.reg_write(UC_X86_REG_EAX, fd)
        else:
            logi(f"int80 open({p!r}, {ecx:#x}) -> -1")
            uc.reg_write(UC_X86_REG_EAX, 0xffffffff)
    elif eax == 3:  # read(fd, buf, count)
        d = FDS.get(ebx)
        if d is not None:
            chunk = d['data'][d['pos']:d['pos']+edx]; d['pos'] += len(chunk)
            wr(ecx, chunk)
            logi(f"int80 read(fd={ebx} {d['path']!r}, n={edx}) -> {chunk[:48]!r}")
            uc.reg_write(UC_X86_REG_EAX, len(chunk))
        else:
            logi(f"int80 read(fd=0x{ebx:x}, n={edx}) -> 0")
            uc.reg_write(UC_X86_REG_EAX, 0)
    elif eax == 6:  # close
        uc.reg_write(UC_X86_REG_EAX, 0)
    elif eax == 20:  # getpid
        uc.reg_write(UC_X86_REG_EAX, 4242)
    elif eax == 64:  # getppid
        logi("int80 getppid() -> 123")
        uc.reg_write(UC_X86_REG_EAX, 123)
    elif eax == 90:
        s = struct.unpack('<6I', rd(ebx, 24))
        addr, length, prot, flags, fd, off = s
        logi(f"int80 old_mmap: addr=0x{addr:x} len=0x{length:x} prot={prot} flags=0x{flags:x}")
        if flags & 0x10 and addr:
            st, en = addr & ~0xfff, (addr+length+0xfff) & ~0xfff
            p = st
            while p < en:
                try: uc.mem_map(p, 0x1000, UC_PROT_ALL)
                except UcError: pass
                p += 0x1000
            uc.reg_write(UC_X86_REG_EAX, addr)
        else:
            global heap_cur
            p = heap_cur[0]; heap_cur[0] = (length + 0xfff) & ~0xfff + p
            uc.reg_map = None
            uc.reg_write(UC_X86_REG_EAX, p)
    elif eax == 192:
        logi(f"int80 mmap2: addr=0x{ebx:x} len=0x{ecx:x} prot={edx}")
        uc.reg_write(UC_X86_REG_EAX, ebx if ebx else 0x6a000000)
    elif eax == 125:
        logi(f"int80 mprotect(0x{ebx:x}, 0x{ecx:x}, {edx})")
        uc.reg_write(UC_X86_REG_EAX, 0)
    elif eax in (1, 252):
        logi(f"int80 exit({ebx})"); uc.emu_stop()
    elif eax == 122:  # uname
        wr(ebx, b'Linux\x00' + b'\x00'*59); uc.reg_write(UC_X86_REG_EAX, 0)
    else:
        logi(f"int80 syscall {eax} (ebx=0x{ebx:x} ecx=0x{ecx:x} edx=0x{edx:x}) -> 0")
        uc.reg_write(UC_X86_REG_EAX, 0)
uc.hook_add(UC_HOOK_INTR, intr_hook)

SENTINEL = 0x9e9e9e9e
def run(addr, label, count=30_000_000):
    cur_fn[0] = label
    esp = STACK - 0x8000
    wr(esp, struct.pack('<I', SENTINEL))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, STACK - 0x10000)
    for r in (UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI):
        uc.reg_write(r, 0)
    insn[0] = 0
    try:
        uc.emu_start(addr, SENTINEL, count=count)
        st = "ok"
    except UcError as e:
        st = f"{e} @eip=0x{uc.reg_read(UC_X86_REG_EIP):x}"
    print(f"== {label} @0x{addr:x}: {st} ({insn[0]} insns)")
    return st


# ===================== GATE ANALYSIS MAIN =====================
print("\n==== running init_array (63 fns) ====")
ia = struct.unpack('<63I', orig[0x7782c:0x7782c+252])
ok = 0
for i, fn in enumerate(ia):
    if fn == 0: continue
    st = run(fn, f"init_array[{i}]", count=12_000_000)
    if st == "ok": ok += 1
print(f"init_array: {ok}/{len(ia)} completed cleanly")

CTX = struct.unpack('<I', rd(0xE7A24, 4))[0]
print(f"\ncontext handle *(0xE7A24) = 0x{CTX:x}")
fnmap = {}
for line in open('/home/z/youcine-re/Youcine-RE/static-analysis/ghidra-exports/unpacked-funcs.txt'):
    if line.startswith('FUNC '):
        p = line.split()
        fnmap[int(p[1],16)] = 0
def fn_of(a):
    return "FUN_%08x" % a if a in fnmap else None
if CTX:
    vtbl = struct.unpack('<I', rd(CTX, 4))[0]
    print(f"ctx->vtbl(=*(ctx)) = 0x{vtbl:x}")
    print("---- vtbl dump (offset -> value -> fn) ----")
    for off in range(0, 0x400, 4):
        try:
            v = struct.unpack('<I', rd(vtbl + off, 4))[0]
        except Exception:
            break
        f = fn_of(v)
        if v and (f or off in (0x38, 0x40, 0x74, 0x188, 0x18c, 0x1a8, 0x1d8)):
            print(f"  vtbl+0x{off:03x} = 0x{v:08x} {f or ''}")
    try:
        sub = struct.unpack('<I', rd(vtbl + 0x38, 4))[0]
        print(f"*(vtbl+0x38) = 0x{sub:x}  (check object)")
        for off in range(0, 0x40, 4):
            v = struct.unpack('<I', rd(sub + off, 4))[0]
            print(f"    sub+0x{off:02x} = 0x{v:08x} {fn_of(v) or ''}")
        chk = struct.unpack('<I', rd(sub + 0x10, 4))[0]
        print(f"check fn *(sub+0x10) = 0x{chk:x}")
    except Exception as e:
        print("vtbl read fail:", e)
    for off, nm in ((0x74,'sdk?'), (0x188,'str?'), (0x18c,'classtable'), (0x1a8,'expected_tracerpid'), (0x1d8,'counter')):
        try:
            v = struct.unpack('<I', rd(vtbl + off, 4))[0]
            extra = ''
            if off in (0x188,):
                try: extra = repr(cstr(v, 80))
                except Exception: pass
            print(f"  vtbl+0x{off:x} ({nm}) = 0x{v:08x} {extra}")
        except Exception:
            pass

def gate_trace(uc, addr, size, ud):
    if addr == 0x61583:
        eax = uc.reg_read(UC_X86_REG_EAX)
        try:
            tgt = struct.unpack('<I', rd(eax + 0x10, 4))[0]
        except Exception:
            tgt = -1
        print(f"*** GATE: vtbl+0x38 obj=0x{eax:x} -> indirect check call to 0x{tgt:x} ***")
    elif addr == 0x6158a:
        print("*** GATE RESULT: check==0 (CLEAN) -> flag 0xF82CC := 1, RegisterNatives ENABLED ***")
    elif addr == 0x6159e:
        print("*** GATE RESULT: check!=0 (DETECTED) -> flag stays 0, RegisterNatives SKIPPED ***")
    elif addr == 0x615d3:
        print("*** GATE: raw int80 getpid (detected branch) ***")
uc.hook_add(UC_HOOK_CODE, gate_trace, begin=0x61560, end=0x61700)

print("\n==== calling gate fn 0x61560 (flag setter) ====")
st = run(0x61560, "gate_fn", count=25_000_000)
flag = rd(0xF82CC, 1)[0]
print(f"run: {st}; flag @0xF82CC = {flag}")
print("hot buckets (addr x ~count):")
for a, c in hist.most_common(15):
    print(f"   0x{a:x} x {c*4}")

# ---- now try the register function with a fake JNIEnv ----
print("\n==== calling register fn 0x5d580 with fake JNIEnv (flag=%d) ====" % flag)
VM      = 0x50000000; VMFN  = 0x50000100
ENV     = 0x50100000; ENVTB = 0x50100100
ENVFN   = 0x50200000
VMFN_T  = 0x50010000
jclass_ctr = [0x54000000]
jstrings = {}
js_ctr = [0x55000000]
for a, sz in [(VM,0x1000),(ENV,0x1000),(ENVFN,0x20000),(VMFN_T,0x1000),(0x54000000,0x1000),(0x55000000,0x10000)]:
    try: uc.mem_map(a, sz, UC_PROT_ALL)
    except UcError: pass
wr(VM, struct.pack('<I', VMFN))
wr(ENV, struct.pack('<I', ENVTB))
tb = b''.join(struct.pack('<I', ENVFN + 32*i) for i in range(240))
wr(ENVTB, tb)
wr(VMFN, b''.join(struct.pack('<I', VMFN_T + 32*i) for i in range(8)))

JNI_NAMES = {4:'GetVersion',6:'FindClass',17:'GetSuperclass',31:'Throw',32:'ThrowNew',33:'ExceptionOccurred',
    34:'ExceptionClear',36:'FatalError',38:'NewGlobalRef',39:'DeleteGlobalRef',40:'DeleteLocalRef',
    50:'GetMethodID',113:'GetFieldID',115:'SetObjectField',192:'GetStaticMethodID',193:'CallStaticObjectMethod',
    215:'RegisterNatives',216:'UnregisterNatives',219:'GetJavaVM',167:'NewString',171:'NewStringUTF',
    173:'GetStringUTFChars',174:'ReleaseStringUTFChars',175:'GetArrayLength',176:'NewObjectArray',
    177:'GetObjectArrayElement',178:'SetObjectArrayElement',30:'DefineClass'}
def jni_hook(uc, addr, size, ud):
    if ENVFN <= addr < ENVFN+0x20000:
        idx = (addr - ENVFN)//32
        name = JNI_NAMES.get(idx, f'env[{idx}]')
        if idx == 215:
            env, clazz, meth, n = arg(0), arg(1), arg(2), arg(3)
            logi(f"*** RegisterNatives(clazz=0x{clazz:x}, methods=0x{meth:x}, n={n}) ***")
            for i in range(n):
                nm, sig, fn = struct.unpack('<III', rd(meth+12*i, 12))
                logi(f"    native [{i}] name={cstr(nm)!r} sig={cstr(sig)!r} fn=0x{fn:x}")
            ret(n)
        elif idx == 6:
            nm = cstr(arg(1))
            c = jclass_ctr[0]; jclass_ctr[0] += 0x10
            logi(f"FindClass({nm!r}) -> 0x{c:x}")
            ret(c)
        elif idx == 171:
            s = cstr(arg(1))
            js = js_ctr[0]; js_ctr[0] += 0x20
            jstrings[js] = s
            logi(f"NewStringUTF({s!r}) -> 0x{js:x}")
            ret(js)
        elif idx == 173:
            js = arg(1)
            s = jstrings.get(js, '<?>')
            buf = h_malloc(len(s)+1); wr(buf, s.encode()+b'\x00')
            logi(f"GetStringUTFChars(0x{js:x}) -> {s!r}")
            ret(buf)
        elif idx in (33, 34, 184, 228):
            ret(0)
        elif idx == 4:
            ret(0x10006)
        elif idx == 219:
            wr(arg(1), struct.pack('<I', VM)); ret(0)
        else:
            if idx not in (178, 175, 181):
                logi(f"JNIEnv {name}(0x{arg(0):x}, 0x{arg(1):x}, 0x{arg(2):x}) -> 0")
            ret(0)
    elif VMFN_T <= addr < VMFN_T + 0x1000:
        idx = (addr - VMFN_T)//32
        # JNIInvokeInterface: 3 reserved, DestroyVM=3, AttachCurrentThread=4, Detach=5, GetEnv=6, AttachAsDaemon=7
        if idx == 6:
            wr(arg(1), struct.pack('<I', ENV)); logi("JavaVM->GetEnv(vm, &env, ver) -> 0 (fake JNIEnv)"); ret(0)
        elif idx == 4:
            wr(arg(1), struct.pack('<I', ENV)); logi("JavaVM->AttachCurrentThread -> fake JNIEnv"); ret(0)
        elif idx == 5:
            logi("JavaVM->DetachCurrentThread -> 0"); ret(0)
        else:
            logi(f"JavaVM->vm[{idx}] -> 0"); ret(0)
uc.hook_add(UC_HOOK_CODE, jni_hook, begin=ENVFN, end=ENVFN+0x20000)
uc.hook_add(UC_HOOK_CODE, jni_hook, begin=VMFN_T, end=VMFN_T+0x1000)

# cdecl call 0x5cbc0(JavaVM* vm, void* reserved)  -- the REAL exported JNI_OnLoad
base = STACK - 0x20000
wr(base, struct.pack('<I', SENTINEL))     # return addr
wr(base+4, struct.pack('<I', VM))         # arg1 = JavaVM*
wr(base+8, struct.pack('<I', 0))          # arg2 = reserved
uc.reg_write(UC_X86_REG_ESP, base)
uc.reg_write(UC_X86_REG_EBP, STACK - 0x30000)
for r in (UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI):
    uc.reg_write(r, 0)
insn[0] = 0
cur_fn[0] = 'JNI_OnLoad_0x5cbc0'
TRACE = _os.environ.get('IJM_TRACE') == '1'
trace = []
def trace_hook(uc, addr, size, ud):
    if len(trace) < 20000:
        trace.append(addr)
if TRACE:
    uc.hook_add(UC_HOOK_CODE, trace_hook, begin=1, end=0x100000)
flag_before = rd(0xF82CC, 1)[0]
try:
    uc.emu_start(0x5cbc0, SENTINEL, count=60_000_000)
    print(f"== JNI_OnLoad: ok ({insn[0]} insns), ret={uc.reg_read(UC_X86_REG_EAX):#x}, flag_before={flag_before} flag_after={rd(0xF82CC,1)[0]}")
except UcError as e:
    print(f"== JNI_OnLoad: {e} @eip=0x{uc.reg_read(UC_X86_REG_EIP):x} ({insn[0]} insns)")
print("hot buckets (JNI_OnLoad):")
for a, c in hist.most_common(10):
    print(f"   0x{a:x} x {c*4}")
if TRACE:
    open('/tmp/unpack-exec/jni_trace.txt', 'w').write('\n'.join(f"0x{a:x}" for a in trace))
    print(f"trace ({len(trace)} insns) -> /tmp/unpack-exec/jni_trace.txt; tail:")
    for a in trace[-40:]:
        print(f"   0x{a:x}")

print("\n==== FULL GATE LOG ====")
for l in log:
    print(" ", l)
open('/tmp/unpack-exec/gate_log.txt', 'w').write('\n'.join(log))
print(f"\nfull log saved: /tmp/unpack-exec/gate_log.txt ({len(log)} lines)")
