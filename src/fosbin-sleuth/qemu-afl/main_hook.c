//
// Created by derrick on 12/7/18.
//

/*
 * Hook main() using LD_PRELOAD, because why not?
 * Obviously, this code is not portable. Use at your own risk.
 *
 * Compile using 'gcc hax.c -o hax.so -fPIC -shared -ldl'
 * Then run your program as 'LD_PRELOAD=$PWD/hax.so ./a.out'
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <FuzzResults.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>
#include <ucontext.h>
#include <pmparser.h>

void usage() {
    printf("Usage: <offset from main> /file/path/to/binary/register/values \n");
}

/* Just assume every target takes 6 full register arguments */
static uint64_t (*fuzz_target)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

struct FuzzingResult fuzzResult;
void *orig_main;
jmp_buf jb;
long target;
int segfault_count;

void reset_buffer(struct FuzzingBuffer *fuzzbuf) {
    uintptr_t *buf = (uintptr_t*)fuzzbuf->location;
    for(size_t i = 0; i < fuzzbuf->length / sizeof(uintptr_t); i++) {
        buf[i] = &buf[i + 1];
    }
    buf[fuzzbuf->length / sizeof(uintptr_t) - 1] = buf;
}

void create_input_pointer(struct FuzzingRegister* reg_ptr) {
        reg_ptr->is_pointer = 1;
        uintptr_t *buf = (uintptr_t*)malloc(reg_ptr->buffer.length);
        reg_ptr->buffer.location = (uintptr_t)buf;
        reset_buffer(buf);
}

void fix_segfaults() {
    for(int i = 0; i < NREGS; i++) {
        if(fuzzResult.preexecution.regs[i].is_pointer) {
            reset_buffer(&fuzzResult.preexecution.regs[i].buffer);
        }
    }
    /* TODO: Add different pointers */
}

void segfault_handler(int signal, siginfo_t *info, void *ucontext) {
    ucontext_t *context = (ucontext_t *) ucontext;
    mcontext_t mcontext = context->uc_mcontext;
    greg_t rip = mcontext.gregs[REG_RIP];

    printf("SEGFAULT AT %p ACCESSING %p\n", rip, info->si_addr);
    fix_segfaults();
    longjmp(jb, ++segfault_count);
}

void register_segfault_handler() {
    struct sigaction act;
    bzero(&act, sizeof(act));
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = segfault_handler;
    errno = 0;
    if (sigaction(SIGSEGV, &act, NULL)) {
        fprintf(stderr, "Could not install SIGSEGV handler: %s\n", strerror(errno));
        exit(1);
    }
}

int is_valid_pointer(uintptr_t ptr, struct FuzzingBuffer *buf) {
    int result = 0;
    procmaps_struct* maps = pmparser_parse(getpid());
    if(maps == NULL) {
        fprintf(stderr, "Could not parse proc maps");
        return -1;
    }

    procmaps_struct* tmp = NULL;
    while((tmp = pmparser_next()) != NULL) {
        if(tmp->addr_start <= ptr && tmp->addr_end >= ptr) {
            if(tmp->is_r && tmp->is_w) {
                buf->location = ptr;
                buf->length = tmp->addr_end - ptr;
                result = 1;
                break;
            }
        }
    }

    pmparser_free(maps);
    return result;
}

/* Our fake main() that gets called by __libc_start_main() */
int main_hook(int argc, char **argv, char **envp) {
    if (argc != 3) {
        usage();
        exit(1);
    }

//    volatile int i = 0;
//    printf("Waiting for debugger to attach to %d\n", getpid());
//    while(!i) {
//        usleep(10000);
//    }

    target = strtol(argv[1], NULL, 0);
    if (!target) {
        fprintf(stderr, "\nCould not find %s!\n", argv[1]);
        exit(1);
    }
    fuzz_target = (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)) target;

    FILE *f = fopen(argv[2], "rb");
    /* The input file format should be the following
     * struct FuzzingRegister rdi
     */
    for(int i = 0; i < NREGS; i++) {
        fread(&fuzzResult.preexecution.regs[i].value, sizeof(fuzzResult.preexecution.regs[i].value), 1, f);
    }
//    for(int i = 0; i < NREGS; i++) {
//        if(fuzzResult.preexecution.regs[i].is_pointer) {
//            if(fuzzResult.preexecution.regs[i].buffer.length > 0) {
//                void *buf = malloc(fuzzResult.preexecution.regs[i].buffer.length);
//                size_t bytes_read = fread(buf, fuzzResult.preexecution.regs[i].buffer.length, 1, f);
//                if(bytes_read != fuzzResult.preexecution.regs[i].buffer.length) {
//                    free(buf);
//                    create_input_pointer(&fuzzResult.preexecution.regs[i]);
//                } else {
//                    fuzzResult.preexecution.regs[i].buffer.location = (uintptr_t)buf;
//                }
//            } else {
//                create_input_pointer(&fuzzResult.preexecution.regs[i]);
//            }
//        }
//    }
    fclose(f);

    if (setjmp(jb) > MAX_TRIES) {
        goto exit;
    }
//    register_segfault_handler();

    fuzzResult.postexecution.ret.value =
            fuzz_target(fuzzResult.preexecution.regs[0].value, fuzzResult.preexecution.regs[1].value,
                        fuzzResult.preexecution.regs[2].value, fuzzResult.preexecution.regs[3].value,
                        fuzzResult.preexecution.regs[4].value, fuzzResult.preexecution.regs[5].value);

    register uint64_t rdi asm("rdi");
    register uint64_t rsi asm("rsi");
    register uint64_t rdx asm("rdx");
    register uint64_t rcx asm("rcx");
    register uint64_t r8 asm("r8");
    register uint64_t r9 asm("r9");

    fuzzResult.postexecution.regs[0].value = rdi;
    fuzzResult.postexecution.regs[1].value = rsi;
    fuzzResult.postexecution.regs[2].value = rdx;
    fuzzResult.postexecution.regs[3].value = rcx;
    fuzzResult.postexecution.regs[4].value = r8;
    fuzzResult.postexecution.regs[5].value = r9;

//    for(int i = 0; i < NREGS; i++) {
//        if(is_valid_pointer(fuzzResult.postexecution.regs[i].value,
//                &fuzzResult.postexecution.regs[i].buffer) > 0) {
//            fuzzResult.postexecution.regs[i].is_pointer = 1;
//        }
//    }
//    if(is_valid_pointer(fuzzResult.postexecution.ret.value,
//            &fuzzResult.postexecution.ret.buffer) > 0) {
//        fuzzResult.postexecution.ret.is_pointer = 1;
//    }

    FILE *out = fopen("fuzz-results.bin", "wab");
    fwrite(&fuzzResult, sizeof(fuzzResult), 1, out);
//    for(int i = 0; i < NREGS; i++) {
//        if(fuzzResult.preexecution.regs[i].is_pointer) {
//            fwrite(fuzzResult.preexecution.regs[i].buffer.location,
//                   fuzzResult.preexecution.regs[i].buffer.length,
//                   1, out);
//        }
//    }
//    for(int i = 0; i < NREGS; i++) {
//        if(fuzzResult.postexecution.regs[i].is_pointer) {
//            fwrite(fuzzResult.postexecution.regs[i].buffer.location,
//                    fuzzResult.postexecution.regs[i].buffer.length,
//                    1, out);
//        }
//    }
//    if(fuzzResult.postexecution.ret.is_pointer) {
//        fwrite(fuzzResult.postexecution.ret.buffer.location,
//                fuzzResult.postexecution.ret.buffer.length,
//                1, out);
//    }
    fclose(out);

    exit:
    return 0;
}

/*
 * Wrapper for __libc_start_main() that replaces the real main
 * function with our hooked version.
 */
int __libc_start_main(
        int (*main)(int, char **, char **),
        int argc,
        char **argv,
        int (*init)(int, char **, char **),
        void (*fini)(void),
        void (*rtld_fini)(void),
        void *stack_end) {
    orig_main = main;

    /* Find the real __libc_start_main()... */
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

    volatile int i = 0;
    printf("Waiting for debugger to attach to %d\n", getpid());
    while(!i) {
        usleep(10000);
    }

    /* afl-fuzz sets argv[0] to be qemu, so ignore that too */
    if (strstr(argv[0], "afl-fuzz") == NULL &&
        strstr(argv[0], "qemu") == NULL) {
        /* ... and call it with our custom main function */
        return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
    } else {
        return orig(orig_main, argc, argv, init, fini, rtld_fini, stack_end);
    }
}