/*
 * trace_guard.c - Youcine-RE iJiami anti-tamper neutralizer.
 *
 * Runs as root ON THE DEVICE. Attaches to the target app process the
 * moment it appears (polls /proc at 5 ms) and follows every thread with
 * PTRACE_SYSCALL, rewriting self-kill and exit syscalls to getpid():
 *
 *   kill(pid, sig) / tgkill / tkill / rt_tgsigqueueinfo / pidfd_send_signal
 *       -> rewritten when sig != 0 (the packer's raw-syscall suicide path)
 *   exit / exit_group
 *       -> always rewritten (the runtime shutdown after the post-decrypt
 *          crash cannot terminate the process either, so the decrypted
 *          DEX stays mapped and the external dumper can sweep at leisure)
 *
 * Forked/cloned children (watchdog threads) are traced automatically via
 * PTRACE_O_TRACE{FORK,CLONE,VFORK}.
 *
 * Build (NDK):
 *   clang --target=x86_64-linux-android24 -O2 -o trace_guard trace_guard.c
 * Usage:
 *   trace_guard <cmdline-needle> <seconds>     # poll for the process
 *   trace_guard <pid> <seconds>                # trace a running pid
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

/* x86_64 syscall numbers */
#define SYS_read_ 0
#define SYS_sched_yield_ 24
#define SYS_getpid_ 39
#define SYS_exit_ 60
#define SYS_kill_ 62
#define SYS_ptrace_ 101
#define SYS_tgkill_ 131
#define SYS_exit_group_ 231
#define SYS_tkill_ 200
#define SYS_rt_tgsigqueueinfo_ 298
#define SYS_pidfd_send_signal_ 424

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_frozen = 0;
static unsigned g_faults = 0;
static unsigned g_ills = 0;

static void on_alrm(int s) { (void)s; g_stop = 1; }
static void on_usr1(int s) { (void)s; g_frozen = 1; }
static void on_usr2(int s) { (void)s; g_frozen = 0; }

static pid_t find_pid(const char *needle)
{
    DIR *d = opendir("/proc");
    if (!d)
        return -1;
    struct dirent *e;
    char path[64];
    char buf[1024];
    pid_t found = -1;
    while ((e = readdir(d))) {
        int p = atoi(e->d_name);
        if (p <= 1)
            continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = 0;
        if (n && strstr(buf, needle)) {
            found = p;
            break;
        }
    }
    closedir(d);
    return found;
}

static int is_pid(const char *s)
{
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

/* returns 1 when the syscall was rewritten */
static int neutralize(pid_t tid, struct user_regs_struct *r)
{
    long nr = (long)r->orig_rax;
    long sig = -1;
    switch (nr) {
    case SYS_kill_:
    case SYS_tkill_:
    case SYS_pidfd_send_signal_:
        sig = (long)r->rsi;
        break;
    case SYS_tgkill_:
    case SYS_rt_tgsigqueueinfo_:
        sig = (long)r->rdx;
        break;
    case SYS_ptrace_:
        /* anti-debug probe: PTRACE_TRACEME fails under a real tracer.
         * fake success by swapping it for sched_yield() which returns 0. */
        if ((long)r->rdi == 0 /* PTRACE_TRACEME */) {
            r->orig_rax = SYS_sched_yield_;
            fprintf(stderr, "[guard] tid %d: faked PTRACE_TRACEME success\n", tid);
            fflush(stderr);
            return 1;
        }
        return 0;
    case SYS_exit_:
    case SYS_exit_group_:
        r->orig_rax = SYS_getpid_;
        fprintf(stderr, "[guard] tid %d: neutralized exit syscall %ld\n", tid, nr);
        fflush(stderr);
        return 1;
    default:
        return 0;
    }
    if (sig > 0) {
        r->orig_rax = SYS_getpid_;
        fprintf(stderr, "[guard] tid %d: neutralized kill syscall %ld (sig %ld)\n", tid, nr, sig);
        fflush(stderr);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid-or-cmdline-needle> <seconds>\n", argv[0]);
        return 2;
    }
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                PTRACE_O_TRACECLONE;

    int dur = atoi(argv[2]);
    signal(SIGALRM, on_alrm);
    signal(SIGINT, on_alrm);
    signal(SIGUSR1, on_usr1);
    signal(SIGUSR2, on_usr2);
    alarm((unsigned)dur);

    const char *needle = is_pid(argv[1]) ? NULL : argv[1];
    pid_t initial = is_pid(argv[1]) ? (pid_t)atoi(argv[1]) : -1;
    int armed_rounds = 0;

    while (!g_stop) {
        pid_t main_pid = initial;
        if (needle) {
            int wait_loops = 0;
            int max_loops = (armed_rounds == 0) ? (dur * 200) : 400;
            while (wait_loops++ < max_loops && !g_stop) {
                main_pid = find_pid(needle);
                if (main_pid > 0)
                    break;
                usleep(5000);
            }
            if (main_pid <= 0) {
                if (armed_rounds > 0)
                    break; /* re-arm window exhausted */
                fprintf(stderr, "[-] target not found within %ds\n", dur);
                return 1;
            }
        }
        if (main_pid <= 0 || g_stop)
            break;
        armed_rounds++;
        fprintf(stderr, "[guard] target pid %d (round %d)\n", main_pid, armed_rounds);

        if (ptrace(PTRACE_ATTACH, main_pid, 0, 0) != 0) {
            perror("PTRACE_ATTACH");
            if (needle)
                continue; /* process may have died; re-arm */
            return 1;
        }
        int status;
        waitpid(main_pid, &status, __WALL);
        if (ptrace(PTRACE_SETOPTIONS, main_pid, 0, opts) != 0)
            perror("SETOPTIONS");
        if (ptrace(PTRACE_SYSCALL, main_pid, 0, 0) != 0)
            perror("PTRACE_SYSCALL");

        if (armed_rounds == 1) {
            fprintf(stderr, "[guard] tracing for %ds (pid written to /data/local/tmp/yc_guard.pid)\n", dur);
            FILE *pf = fopen("/data/local/tmp/yc_guard.pid", "w");
            if (pf) {
                fprintf(pf, "%d\n", getpid());
                fclose(pf);
            }
        }

        /* ---- trace loop ---- */
        int main_alive = 1;
        while (main_alive && !g_stop) {
            pid_t t = waitpid(-1, &status, __WALL);
            if (t < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                fprintf(stderr, "[guard] tracee %d gone (%s %d)\n", t,
                        WIFEXITED(status) ? "exit" : "sig",
                        WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
                if (t == main_pid) {
                    main_alive = 0;
                    break; /* re-arm on the next restart */
                }
                continue;
            }
            if (!WIFSTOPPED(status))
                continue;
            int sig = WSTOPSIG(status);
            unsigned event = (unsigned)status >> 16;

            if (g_frozen && sig == (SIGTRAP | 0x80)) {
                /* hold this tracee at the syscall boundary while frozen */
                while (g_frozen && !g_stop)
                    usleep(20000);
                ptrace(PTRACE_SYSCALL, t, 0, 0);
                continue;
            }

            if (sig == (SIGTRAP | 0x80)) { /* syscall stop */
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, t, 0, &regs) == 0) {
                    if ((long)regs.rax == -ENOSYS) { /* syscall entry */
                        if (neutralize(t, &regs) == 1)
                            ptrace(PTRACE_SETREGS, t, 0, &regs);
                    }
                }
                ptrace(PTRACE_SYSCALL, t, 0, 0);
                continue;
            }
            if (sig == SIGTRAP && event) { /* fork/clone/vfork/exec event */
                unsigned long msg = 0;
                ptrace(PTRACE_GETEVENTMSG, t, 0, &msg);
                pid_t child = (pid_t)msg;
                ptrace(PTRACE_SETOPTIONS, child, 0, opts);
                ptrace(PTRACE_SYSCALL, child, 0, 0);
                ptrace(PTRACE_SYSCALL, t, 0, 0);
                fprintf(stderr, "[guard] new tracee %d (from %d)\n", child, t);
                continue;
            }
            if (sig == SIGTRAP) {
                /* iJiami INT3 anti-debug probe: swallow the trap and let
                 * execution continue past the int3 instruction. */
                fprintf(stderr, "[guard] tid %d: swallowed SIGTRAP (int3 probe)\n", t);
                fflush(stderr);
                ptrace(PTRACE_SYSCALL, t, 0, 0);
                continue;
            }
            if (sig == SIGILL) {
                /* iJiami deliberate ud2 crash: skip the instruction so
                 * execution falls through the tamper branch (same trick
                 * that worked for the int3 probes). */
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, t, 0, &regs) == 0) {
                    errno = 0;
                    long word = ptrace(PTRACE_PEEKDATA, t,
                                       (void *)(uintptr_t)regs.rip, 0);
                    if (errno == 0) {
                        unsigned b0 = (unsigned)(word & 0xff);
                        unsigned b1 = (unsigned)((word >> 8) & 0xff);
                        if (b0 == 0x0f && b1 == 0x0b) {
                            regs.rip += 2; /* ud2 is 2 bytes */
                            ptrace(PTRACE_SETREGS, t, 0, &regs);
                            g_ills++;
                            if (g_ills <= 5 || (g_ills % 100000) == 0) {
                                fprintf(stderr,
                                        "[guard] tid %d: skipped ud2 at %llx (total %u)\n",
                                        t, (unsigned long long)regs.rip, g_ills);
                                fflush(stderr);
                            }
                            ptrace(PTRACE_SYSCALL, t, 0, 0);
                            continue;
                        }
                        if (g_ills < 3) {
                            fprintf(stderr,
                                    "[guard] tid %d: SIGILL at %llx bytes %02x %02x %02x %02x (not ud2, pinning)\n",
                                    t, (unsigned long long)regs.rip,
                                    b0, b1, (unsigned)((word >> 16) & 0xff),
                                    (unsigned)((word >> 24) & 0xff));
                            fflush(stderr);
                        }
                    }
                }
                ptrace(PTRACE_SYSCALL, t, 0, 0);
                continue;
            }
            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS ||
                sig == SIGFPE) {
                /* Deliberate crash (anti-tamper ladder step): suppress the
                 * signal. The faulting instruction re-executes and faults
                 * again in a tight loop - the thread burns one core but the
                 * process stays ALIVE with all memory (incl. any decrypted
                 * DEX) intact for the external dumper. */
                g_faults++;
                if (g_faults <= 5 || (g_faults % 100000) == 0) {
                    fprintf(stderr, "[guard] tid %d: suppressed fault signal %d (total %u)\n",
                            t, sig, g_faults);
                    fflush(stderr);
                }
                ptrace(PTRACE_SYSCALL, t, 0, 0);
                continue;
            }
            if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                ptrace(PTRACE_SYSCALL, t, 0, 0); /* suppress group-stop signals */
                continue;
            }
            ptrace(PTRACE_SYSCALL, t, 0, sig); /* relay */
        }
        if (needle && !g_stop) {
            fprintf(stderr, "[guard] main tracee died; re-arming\n");
            usleep(300000);
        }
    }
    fprintf(stderr, "[guard] done\n");
    return 0;
}
