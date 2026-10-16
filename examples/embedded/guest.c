#include "guest_abi.h"
static void done(long status) {
    call(NR_EXIT, status, 0, 0);
    __builtin_unreachable();
}
#define CHECK(condition, status) do { if (!(condition)) done(status); } while (0)
__attribute__((used, noinline)) long unavailable(long value) { return -1; }

void _start(void) {
    long answer;
    HOOK("demo", answer);
    CHECK(answer == 42, 11);
    long fd = call(NR_OPEN, (long)"/guestweave/demo-bytes", 0, 0);
    CHECK(fd >= 0, 12);
    char bytes[4];
    CHECK(call(NR_READ, fd, (long)bytes, 1) == 1 && bytes[0] == 'A', 13);
    long duplicate = call(NR_DUP, fd, 0, 0);
    CHECK(duplicate >= 0, 14);
    CHECK(call(NR_READ, duplicate, (long)bytes, 3) == 2 && bytes[0] == 'B' && bytes[1] == 'C', 15);
    CHECK(call(NR_READ, fd, (long)bytes, 1) == 0, 16);
    CHECK(call(NR_WRITE, duplicate, (long)"x", 1) == -ERR_NOSYS, 17); /* owned: ENOSYS */
    CHECK(call(NR_CLOSE, fd, 0, 0) == 0 && call(NR_CLOSE, duplicate, 0, 0) == 0, 18);
    /* A new open has independent state; aliases reuse the same implementation. */
    fd = call(NR_OPEN, (long)"/guestweave/demo-alias", 0, 0);
    CHECK(fd >= 0 && call(NR_READ, fd, (long)bytes, 1) == 1 && bytes[0] == 'A', 19);
    CHECK(call(NR_CLOSE, fd, 0, 0) == 0, 20);
    /* No launcher was configured: do not drop instrumentation via native exec. */
    static const char *argv[] = {"/guestweave/missing-image", 0};
    static const char *env[] = {0};
    CHECK(call(NR_EXECVE, (long)argv[0], (long)argv, (long)env) == -ERR_NOSYS, 21);
    CHECK(call(NR_WRITE, 1, (long)"embedded-guest-ok\n", 18) == 18, 22);
    done(0);
}
