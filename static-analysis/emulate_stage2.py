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
MODE = sys.argv[3] if len(sys.argv) > 3 else "init"
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

def h_malloc(n): 
    p = heap_cur[0]; heap_cur[0] += (n + 15) & ~15
    return p
FILECTR = [0x61000000]
FILES = {}
def h_fopen(path, mode):
    p = cstr(path)
    logi(f"fopen({p!r}, {mode})")
    f = FILECTR[0]; FILECTR[0] += 0x100
    FILES[f] = {'path': p, 'pos': 0, 'data': b''}
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
        # fgets(buf, size, FILE*) -> NULL
        logi(f"fgets(?, {arg(1)}, fp=0x{arg(2):x}) -> NULL"); ret(0)
    elif name == 'fread':
        logi(f"fread(n={arg(2)})"); ret(0)
    elif name in ('__android_log_write',):
        logi(f"log_write: {cstr(arg(2))!r} {cstr(arg(3))!r}"); ret(0)
    elif name == 'ptrace':
        logi(f"ptrace(req={arg(0)}, pid={arg(1)}) -> 0"); ret(0)
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
        logi(f"dlsym(handle=0x{arg(0):x}, {sname!r}) -> 0"); ret(0)
    elif name == 'dlclose': ret(0)
    elif name == 'open' or name == '__open_2':
        logi(f"open({cstr(arg(0))!r}, flags={arg(1)}) -> -1"); ret(0xffffffff)
    elif name == 'read': logi(f"read(fd={arg(0)}, n={arg(2)}) -> 0"); ret(0)
    elif name == 'close': ret(0)
    elif name == 'lseek64' or name == 'lseek': ret(0)
    elif name == 'stat' or name == 'lstat' or name == 'fstat': ret(0xffffffff)
    elif name == 'access': logi(f"access({cstr(arg(0))!r}, {arg(1)}) -> -1"); ret(0xffffffff)
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
    if eax == 90:
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

# init_array entries (from original file: vaddr 0xe782c -> file 0x7782c, 63*4 bytes)
ia = struct.unpack('<63I', orig[0x7782c:0x7782c+252])
ok = 0
if MODE in ('init', 'all'):
    for i, fn in enumerate(ia):
        if fn == 0: continue
        st = run(fn, f"init_array[{i}]")
        if st == "ok": ok += 1
    print(f"init_array: {ok}/{len(ia)} completed cleanly")

if MODE in ('jni', 'all'):
    # ---- fake JNI environment ----
    VM      = 0x50000000; VMFN  = 0x50000100
    ENV     = 0x50100000; ENVTB = 0x50100100
    ENVFN   = 0x50200000          # env function trampolines (i*32)
    VMFN_T  = 0x50010000          # vm  function trampolines (i*32)
    jclass_ctr = [0x54000000]
    jstrings = {}
    js_ctr = [0x55000000]
    for a, sz in [(VM,0x1000),(ENV,0x1000),(ENVFN,0x20000),(VMFN_T,0x1000),(0x54000000,0x1000),(0x55000000,0x10000)]:
        uc.mem_map(a, sz, UC_PROT_ALL)
    wr(VM, struct.pack('<I', VMFN))
    wr(ENV, struct.pack('<I', ENVTB))
    # env functions table: 233 slots of trampoline pointers
    tb = b''.join(struct.pack('<I', ENVFN + 32*i) for i in range(240))
    wr(ENVTB, tb)
    wr(VMFN, b''.join(struct.pack('<I', VMFN_T + 32*i) for i in range(8)))

    JNI_NAMES = {4:'GetVersion',6:'FindClass',7:'FromReflectedMethod',9:'ToReflectedMethod',
        17:'GetSuperclass',31:'Throw',32:'ThrowNew',33:'ExceptionOccurred',34:'ExceptionClear',
        36:'FatalError',38:'NewGlobalRef',39:'DeleteGlobalRef',40:'DeleteLocalRef',
        41:'IsSameObject',42:'NewLocalRef',43:'EnsureLocalCapacity',44:'AllocObject',
        45:'NewObject',46:'NewObjectV',47:'NewObjectA',48:'GetObjectClass',49:'IsInstanceOf',
        50:'GetMethodID',51:'CallObjectMethod',113:'GetFieldID',115:'SetObjectField',
        94:'RegisterNatives_x',  # placeholder
        113+95:'GetStaticFieldID',
        215:'RegisterNatives',216:'UnregisterNatives',217:'MonitorEnter',218:'MonitorExit',
        219:'GetJavaVM',167:'NewString',168:'GetStringLength',169:'GetStringChars',
        170:'ReleaseStringChars',171:'NewStringUTF',172:'GetStringUTFLength',
        173:'GetStringUTFChars',174:'ReleaseStringUTFChars',175:'GetArrayLength',
        176:'NewObjectArray',177:'GetObjectArrayElement',178:'SetObjectArrayElement',
        192:'GetStaticMethodID',193:'CallStaticObjectMethod',
        30:'DefineClass',113+107:'CallStaticVoidMethod',
        }
    def jni_hook(uc, addr, size, ud):
        if ENVFN <= addr < ENVFN+0x20000:
            idx = (addr - ENVFN)//32
            name = JNI_NAMES.get(idx, f'env[{idx}]')
            if idx == 215:  # RegisterNatives(env, clazz, methods, n)
                env, clazz, meth, n = arg(0), arg(1), arg(2), arg(3)
                logi(f"*** RegisterNatives(clazz=0x{clazz:x}, methods=0x{meth:x}, n={n}) ***")
                for i in range(n):
                    nm, sig, fn = struct.unpack('<III', rd(meth+12*i, 12))
                    logi(f"    native [{i}] name={cstr(nm)!r} sig={cstr(sig)!r} fn=0x{fn:x}")
                ret(n)
            elif idx == 6:  # FindClass(env, name)
                nm = cstr(arg(1))
                c = jclass_ctr[0]; jclass_ctr[0] += 0x10
                logi(f"FindClass({nm!r}) -> 0x{c:x}")
                ret(c)
            elif idx == 171:  # NewStringUTF(env, chars)
                s = cstr(arg(1))
                js = js_ctr[0]; js_ctr[0] += 0x20
                jstrings[js] = s
                logi(f"NewStringUTF({s!r}) -> 0x{js:x}")
                ret(js)
            elif idx == 173:  # GetStringUTFChars
                js = arg(1)
                s = jstrings.get(js, '<?>' )
                buf = h_malloc(len(s)+1); wr(buf, s.encode()+b'\x00')
                logi(f"GetStringUTFChars(0x{js:x}) -> {s!r}")
                ret(buf)
            elif idx in (33, 34, 184, 228):  # exception checks
                ret(0)
            elif idx == 4:
                ret(0x10006)  # JNI_VERSION_1_6
            elif idx == 219:
                wr(arg(1), struct.pack('<I', VM)); ret(0)
            else:
                if idx not in (178, 175, 181):
                    logi(f"JNIEnv call {name}(0x{arg(0):x}, 0x{arg(1):x}, 0x{arg(2):x}) -> 0")
                ret(0)
        elif VMFN_T <= addr < VMFN_T + 0x1000:
            idx = (addr - VMFN_T)//32
            vmn = {0:'DestroyVM',1:'AttachCurrentThread',2:'DetachCurrentThread',3:'GetEnv',4:'AttachAsDaemon'}.get(idx, f'vm[{idx}]')
            if idx == 3:  # GetEnv(vm, &env, version)
                wr(arg(1), struct.pack('<I', ENV)); logi("JavaVM->GetEnv -> fake JNIEnv")
                ret(0)
            elif idx == 1:
                wr(arg(1), struct.pack('<I', ENV)); logi("JavaVM->AttachCurrentThread -> fake JNIEnv"); ret(0)
            else:
                logi(f"JavaVM->{vmn} -> 0"); ret(0)
    uc.hook_add(UC_HOOK_CODE, jni_hook, begin=ENVFN, end=ENVFN+0x20000)
    uc.hook_add(UC_HOOK_CODE, jni_hook, begin=VMFN_T, end=VMFN_T+0x1000)

    # call JNI_OnLoad(vm, NULL)
    cur_fn[0] = 'JNI_OnLoad'
    esp = STACK - 0x8000
    wr(esp, struct.pack('<II', SENTINEL, VM))
    uc.reg_write(UC_X86_REG_ESP, esp-4)  # push vm as arg1
    # [esp]=vm? cdecl: args pushed right-to-left; call pushes retaddr; emulate:
    wr(esp-4, struct.pack('<I', VM))     # arg1 at [esp_after_call+4]
    wr(esp-8, struct.pack('<I', 0))      # arg2
    wr(esp-12, struct.pack('<I', SENTINEL))  # return addr
    uc.reg_write(UC_X86_REG_ESP, esp-12)
    uc.reg_write(UC_X86_REG_EBP, STACK - 0x10000)
    insn[0] = 0
    try:
        uc.emu_start(0x5cbc0, SENTINEL, count=60_000_000)
        print(f"== JNI_OnLoad: ok ({insn[0]} insns), ret={uc.reg_read(UC_X86_REG_EAX):#x}")
    except UcError as e:
        print(f"== JNI_OnLoad: {e} @eip=0x{uc.reg_read(UC_X86_REG_EIP):x} ({insn[0]} insns)")
    print("hot eip buckets (addr x count):")
    for a, c in hist.most_common(25):
        print(f"   0x{a:x} x {c*4}")

# after running, dump the RW segment (strings decrypted in place)
def dump_rw(path='/tmp/unpack-exec/rw_after_init.bin'):
    blob = bytes(uc.mem_read(0xe5c00, 0x12144))
    open(path, 'wb').write(blob)
    print(f"RW after init dumped: {path}")

print("\n==== STAGE-2 LOG (last 120 lines) ====")
for l in log[-120:]:
    print(" ", l)
if MODE in ('init', 'all'):
    dump_rw()
open('/tmp/unpack-exec/stage2_log.txt', 'w').write('\n'.join(log))
print(f"\nfull log: /tmp/unpack-exec/stage2_log.txt ({len(log)} lines)")
