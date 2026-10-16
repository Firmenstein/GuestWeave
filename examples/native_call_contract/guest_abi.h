/* Minimal Linux syscall/call ABI for the freestanding example, not framework API.
 * Numbers follow QEMU's linux-user/{arm,mips,x86_64} syscall tables and errno
 * definitions. MIPS o32 reports errors through a3 and uses ENOSYS = 89.
 */
#if defined(__x86_64__)
#define NR_EXIT 60
#define NR_FORK 57
#define NR_READ 0
#define NR_WRITE 1
#define NR_OPEN 2
#define NR_CLOSE 3
#define NR_EXECVE 59
#define NR_CHDIR 80
#define NR_DUP 32
#define NR_DUP2 33
#define NR_FCNTL 72
#define NR_WAIT4 61
#define ERR_NOSYS 38
static long call(long n, long a, long b, long c) {
    long result;
    register long fourth __asm__("r10") = 0;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(fourth)
        : "rcx", "r11", "memory");
    return result;
}
#define HOOK(prefix, result) do { \
    __asm__ volatile(".global " prefix "_call\n" prefix "_call: call unavailable\n" \
        ".global " prefix "_resume\n" prefix "_resume:\n" \
        : "=a"(result) : "D"(41L) \
        : "rcx", "r11", "rsi", "rdx", "r8", "r9", "r10", "cc", "memory"); \
} while (0)
#define ENTRY \
    __asm__(".text\n.global _start\n_start:\nmov %rsp, %rdi\nand $-16, %rsp\ncall guest_main\nud2\n");
#elif defined(__arm__) || defined(__mips__)
#ifdef __mips__
#define NR_BASE 4000
#define ERR_NOSYS 89
static long call(long n, long a, long b, long c) {
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a;
    register long a1 __asm__("$5") = b;
    register long a2 __asm__("$6") = c;
    register long error __asm__("$7") = 0;
    __asm__ volatile("syscall" : "+r"(v0), "+r"(error)
        : "r"(a0), "r"(a1), "r"(a2) : "memory");
    return error ? -v0 : v0;
}
#define HOOK(prefix, result) do { \
    register long v0 __asm__("$2"); \
    register long arg __asm__("$4") = 41; \
    __asm__ volatile(".set push\n.set noreorder\n.global " prefix "_call\n" \
        prefix "_call: jal unavailable\nnop\n.global " prefix "_resume\n" \
        prefix "_resume:\n.set pop\n" : "=r"(v0), "+r"(arg) : \
        : "$3", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "$31", "hi", "lo", "memory"); \
    result = v0; \
} while (0)
#define ENTRY \
    __asm__(".text\n.set noreorder\n.global _start\n_start:\nmove $4, $sp\naddiu $sp, $sp, -16\njal guest_main\nnop\nbreak\n.set reorder\n");
#else
#define NR_BASE 0
#define ERR_NOSYS 38
static long call(long n, long a, long b, long c) {
    register long r7 __asm__("r7") = n;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = 0;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2), "r"(r3) : "memory");
    return r0;
}
#define HOOK(prefix, result) do { \
    register long arg __asm__("r0") = 41; \
    __asm__ volatile(".global " prefix "_call\n" prefix "_call: bl unavailable\n" \
        ".global " prefix "_resume\n" prefix "_resume:\n" \
        : "+r"(arg) : : "r1", "r2", "r3", "r12", "lr", "cc", "memory"); \
    result = arg; \
} while (0)
#define ENTRY \
    __asm__(".text\n.global _start\n_start:\nmov r0, sp\nbic sp, sp, #7\nbl guest_main\nudf #0\n");
#endif
#define NR_EXIT (NR_BASE + 1)
#define NR_FORK (NR_BASE + 2)
#define NR_READ (NR_BASE + 3)
#define NR_WRITE (NR_BASE + 4)
#define NR_OPEN (NR_BASE + 5)
#define NR_CLOSE (NR_BASE + 6)
#define NR_EXECVE (NR_BASE + 11)
#define NR_CHDIR (NR_BASE + 12)
#define NR_DUP (NR_BASE + 41)
#define NR_DUP2 (NR_BASE + 63)
#define NR_FCNTL (NR_BASE + 55)
#define NR_WAIT4 (NR_BASE + 114)
#else
#error Unsupported example guest architecture
#endif
