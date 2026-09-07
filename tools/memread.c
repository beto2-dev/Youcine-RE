/* memread - dump a byte range from /proc/<pid>/mem at an exact address.
 *
 * Why this exists: the on-device `toybox dd if=/proc/PID/mem skip=N` sweep
 * silently produced nothing for regions at high addresses (> ~0xe90000000000)
 * where ART maps the decrypted "dalvik-DEX data" containers - run evidence
 * 34124326711/34127034994: [anon:dalvik-DEX data] regions of 10.2/7.8/6.1 MB
 * exist in the frozen app's maps, yet the dd sweep returned zero dex magic.
 * This helper does a plain pread64() from the given virtual address, which
 * is immune to any block-size/offset arithmetic quirks in toybox.
 *
 * Compiled statically on the GitHub arm64 runner (gcc -static): a static
 * arm64 Linux ELF runs fine inside the redroid container (plain Linux
 * syscalls, no bionic/glibc dynamic deps).
 *
 * usage: memread <pid> <hexaddr> <size> <outfile>
 * exit:  0 ok, 1 partial, 2 usage/open failure
 */
#define _GNU_SOURCE /* pread64 / off64_t */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <pid> <hexaddr> <size> <outfile>\n",
                argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    unsigned long long addr = strtoull(argv[2], NULL, 16);
    long long size = atoll(argv[3]);
    const char *out_path = argv[4];
    if (pid <= 0 || size <= 0) {
        fprintf(stderr, "bad pid/size\n");
        return 2;
    }

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int mfd = open(mem_path, O_RDONLY);
    if (mfd < 0) {
        fprintf(stderr, "open %s: %s\n", mem_path, strerror(errno));
        return 2;
    }
    int ofd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ofd < 0) {
        fprintf(stderr, "open %s: %s\n", out_path, strerror(errno));
        close(mfd);
        return 2;
    }

    static char buf[1 << 16];
    long long done = 0;
    long long zero_pages = 0;
    while (done < size) {
        long long want = size - done;
        if (want > (long long)sizeof(buf))
            want = sizeof(buf);
        ssize_t r = pread64(mfd, buf, (size_t)want,
                            (off64_t)(addr + (unsigned long long)done));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "pread at 0x%llx: %s\n",
                    addr + (unsigned long long)done, strerror(errno));
            break;
        }
        if (r == 0)
            break;
        /* count all-zero reads for diagnostics (wiped pages) */
        int all_zero = 1;
        for (ssize_t i = 0; i < r; i += 4096) {
            if (buf[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero)
            zero_pages += (r + 4095) / 4096;
        ssize_t w = write(ofd, buf, (size_t)r);
        if (w != r) {
            fprintf(stderr, "write: %s\n", strerror(errno));
            break;
        }
        done += r;
    }
    close(ofd);
    close(mfd);
    fprintf(stderr, "memread pid=%d 0x%llx+%lld -> %s (%lld bytes, %lld zero pages)\n",
            pid, addr, size, out_path, done, zero_pages);
    return (done == size) ? 0 : 1;
}
