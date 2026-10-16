#include "guest_abi.h"

static void done(long status) {
    call(NR_EXIT, status, 0, 0);
    __builtin_unreachable();
}
#define CHECK(condition, status) do { if (!(condition)) done(status); } while (0)

/* Place a second executable section at probe VA + the main load base. The
 * legacy resolver must reject that ambiguity even though probe is valid. */
__attribute__((used, noinline, section(".native_alias"))) void address_alias(void) {
    __asm__ volatile("");
}

#ifdef __mips__
__asm__(".text\n.set push\n.set noreorder\n.global pic_probe\npic_probe:\n"
        "move $10, $31\nbal 1f\nnop\n1: addiu $8, $31, -12\n"
        "bne $25, $8, 2f\nnop\n"
        "lw $9, 0($4)\naddiu $9, $9, 1\nsw $9, 0($4)\n"
        "lw $2, 60($25)\njr $10\nnop\n"
        "2: addiu $2, $0, 99\njr $10\nnop\n.word 603\n.set pop\n");
#else
__attribute__((used, noinline)) long pic_probe(volatile unsigned *bodies) {
    *bodies += 1;
    return 603;
}
#endif

__attribute__((used, noinline)) long probe(unsigned depth, volatile unsigned *entries,
                                         unsigned mode, volatile unsigned *bodies) {
    (void)entries;
    (void)mode;
    *bodies += 1;
    return 40 + depth;
}

static void emit(const char *text, unsigned len) {
    CHECK(call(NR_WRITE, 1, (long)text, len) == len, 90);
}
static void number(unsigned n) {
    char buf[16];
    unsigned len = 0;
    /* Keep the freestanding guest independent of compiler-rt helpers.  ARM
     * would otherwise require __aeabi_uidiv/__aeabi_uidivmod at link time. */
    do {
        unsigned quotient = 0;
        while (n >= 10) { n -= 10; quotient += 1; }
        buf[len++] = '0' + n;
        n = quotient;
    } while (n);
    for (unsigned i = 0; i < (len >> 1); ++i) {
        char tmp = buf[i]; buf[i] = buf[len - i - 1]; buf[len - i - 1] = tmp;
    }
    emit(buf, len);
}

ENTRY
void guest_main(unsigned long *initial_stack) {
    unsigned long argc = initial_stack[0];
    char **argv = (char **)(initial_stack + 1);
    CHECK(argc == 2 && argv[1][0] >= '0' && argv[1][0] <= '5' && argv[1][1] == 0, 91);
    unsigned mode = (unsigned)(argv[1][0] - '0');
    {
        volatile unsigned entries = 0;
        volatile unsigned bodies = 0;
        long result = probe(0, &entries, mode, &bodies);
        emit("mode=", 5); number(mode);
        emit(" result=", 8); number((unsigned)result);
        emit(" hooks=", 7); number(entries);
        emit(" bodies=", 8); number(bodies);
        emit("\n", 1);
        if (mode == 0) CHECK(result == 40 && entries == 1 && bodies == 1, 10);
        // Same-address native_call re-enters the hook twice, then a bounded
        // argument condition replaces the deepest call. No native body runs.
        if (mode == 1) CHECK(result == 900 && entries == 3 && bodies == 0, 11);
        // An explicit re-entry guard lets the nested hook fall through into
        // the native function body exactly once.
        if (mode == 2) CHECK(result == 41 && entries == 2 && bodies == 1, 12);
        // This specific ET_EXEC's offset has one executable relocated candidate;
        // the public API's legacy resolver accepts it and the hook runs again.
        if (mode == 3) CHECK(result == 601 && entries == 2 && bodies == 0, 13);
        if (mode == 4) CHECK(result == 602 && entries == 2 && bodies == 0, 14);
        if (mode == 5) CHECK(result == 603 && entries == 1 && bodies == 1, 15);
    }
    emit("native-call-contract-ok\n", 24);
    done(0);
}
