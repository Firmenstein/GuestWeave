#include "guest_abi.h"
static void done(long code) { call(NR_EXIT, code, 0, 0); __builtin_unreachable(); }
#define CHECK(x, code) do { if (!(x)) done(code); } while (0)
static int equal(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; } return *a == *b;
}
__attribute__((used, noinline)) long unavailable(long value) { return -1; }
__attribute__((used)) static void guest_main(long *stack) {
    long argc = *stack;
    char **argv = (char **)(stack + 1);
    char **env = argv + argc + 1;
    long answer;
    HOOK("exec", answer);
    CHECK(answer == 42, 31); /* Must be installed again after each exec. */
    char bytes[4];
    if (equal(argv[0], "-child,\xff")) {
        CHECK(argc == 3 && equal(argv[1], "arg,\xfe"), 32);
        CHECK(env[0] && equal(env[0], "KEY=a,\xff") && !env[1], 33);
        CHECK(call(NR_READ, 7, (long)bytes, 1) == 1 && bytes[0] == 'B', 34);
        CHECK(call(NR_READ, 8, (long)bytes, 1) == 1 && bytes[0] == 'C', 35);
        CHECK(call(NR_READ, 7, (long)bytes, 1) == 0, 36); /* dup shares OFD */
        CHECK(call(NR_READ, 9, (long)bytes, 1) == -9, 37); /* CLOEXEC */
        CHECK(call(NR_CLOSE, 7, 0, 0) == 0 && call(NR_CLOSE, 8, 0, 0) == 0, 38);
        const char *next[] = {"-last", 0};
        call(NR_EXECVE, (long)argv[2], (long)next, 0); /* NULL envp is empty */
        done(39);
    }
    if (equal(argv[0], "-last")) {
        CHECK(argc == 1 && !env[0], 40);
        long fd = call(NR_OPEN, (long)"/guestweave/demo-alias", 0, 0);
        CHECK(fd >= 0 && call(NR_READ, fd, (long)bytes, 1) == 1 && bytes[0] == 'A', 41);
        CHECK(call(NR_WRITE, 1, (long)"embedded-exec-ok\n", 17) == 17, 42);
        done(0);
    }
    CHECK(argc == 3, 43);
    long fd = call(NR_OPEN, (long)"/guestweave/demo-bytes", 0, 0);
    CHECK(fd >= 0 && call(NR_READ, fd, (long)bytes, 1) == 1 && bytes[0] == 'A', 44);
    CHECK(call(NR_DUP2, fd, 7, 0) == 7 && call(NR_DUP2, fd, 8, 0) == 8, 45);
    CHECK(call(NR_DUP2, fd, 9, 0) == 9 && call(NR_FCNTL, 9, 2, 1) == 0, 46);
    CHECK(call(NR_CLOSE, fd, 0, 0) == 0, 47);
    CHECK(call(NR_CHDIR, (long)"/tmp", 0, 0) == 0, 51); /* worker keeps guest cwd */
    if (equal(argv[1], "empty")) {
        const char *next[] = {"-last", 0};
        call(NR_EXECVE, (long)argv[2], (long)next, 0);
        done(52);
    }
    if (equal(argv[1], "fork")) {
        long child = call(NR_FORK, 0, 0, 0);
        CHECK(child >= 0, 48);
        if (child) {
            int status = -1;
            CHECK(call(NR_WAIT4, child, (long)&status, 0) == child && status == 0, 49);
            done(0);
        }
    }
    const char *next[] = {"-child,\xff", "arg,\xfe", argv[2], 0};
    const char *next_env[] = {"KEY=a,\xff", 0};
    call(NR_EXECVE, (long)argv[2], (long)next, (long)next_env);
    done(50);
}
ENTRY
