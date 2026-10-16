/* QEMU and guest syscalls share a host fd table. A FILE cookie has no fd:
 * guest dup2/close/close_range cannot retarget it. Each diagnostic write opens
 * its destination only for the duration of the callback, before guest resumes.
 * No malloc, stdio recursion, or inherited mutex in this callback (fork/signal).
 * This does not provide fd-table isolation from concurrent guest threads.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char path_prefix[PATH_MAX];
static size_t prefix_length;
static _Atomic unsigned long long written_bytes, failures;
static _Atomic int last_error;

static size_t append_pid(char *out, unsigned long pid) {
    char reverse[32];
    size_t n = 0;
    do { reverse[n++] = '0' + pid % 10; pid /= 10; } while (pid);
    for (size_t i = 0; i < n; i++) out[i] = reverse[n-i-1];
    return n;
}

ssize_t fmst_diagnostics_write(const char *data, size_t length) {
    int saved_errno = errno;
    char path[PATH_MAX];
    memcpy(path, path_prefix, prefix_length);
    size_t n = prefix_length + append_pid(path + prefix_length, getpid());
    memcpy(path + n, ".log", 5);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0666);
    if (fd >= 0) {
        /* This attempt's output mount is already guest-writable. A legitimate
         * setuid must not make a root-created stream impossible to reopen.
         * Set only a newly created artifact's mode, never the guest umask. */
        if (fchmod(fd, 0666) != 0) { int error = errno; close(fd); fd = -1; errno = error; }
    } else if (errno == EEXIST) {
        fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    }
    size_t offset = 0;
    int error = fd < 0 ? errno : 0;
    while (!error && offset < length) {
        ssize_t result = write(fd, data + offset, length - offset);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) { error = result == 0 ? EIO : errno; break; }
        offset += result;
    }
    if (fd >= 0) close(fd);
    atomic_fetch_add(&written_bytes, offset);
    if (error) {
        atomic_fetch_add(&failures, 1);
        atomic_store(&last_error, error);
        errno = error;
        return -1;
    }
    errno = saved_errno;
    return (ssize_t)offset;
}

static ssize_t cookie_write(void *cookie, const char *data, size_t length) {
    (void)cookie;
    return fmst_diagnostics_write(data, length);
}

int fmst_diagnostics_install(const char *prefix) {
    size_t length = strlen(prefix);
    if (length > sizeof(path_prefix) - 40) { errno = ENAMETOOLONG; return -1; }
    memcpy(path_prefix, prefix, length + 1);
    prefix_length = length;
    if (fmst_diagnostics_write("", 0) < 0) return -1;
    cookie_io_functions_t callbacks = { .write = cookie_write };
    FILE *sink = fopencookie(NULL, "w", callbacks);
    if (!sink) return -1;
    setvbuf(sink, NULL, _IONBF, 0);
    /* Do not fclose the old stderr: fd 2 still belongs to the guest. */
    stderr = sink;
    return 0;
}

void fmst_diagnostics_counters(unsigned long long *bytes,
                               unsigned long long *errors, int *error) {
    *bytes = atomic_load(&written_bytes);
    *errors = atomic_load(&failures);
    *error = atomic_load(&last_error);
}
