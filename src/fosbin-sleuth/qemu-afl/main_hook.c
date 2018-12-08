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

/* Just assume every target takes 6 full register arguments */
static uint64_t (*fuzz_target)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

void usage() {
    printf("Usage: <offset from main> /file/path/to/binary/register/values \n");
}

struct FuzzingResult fuzzResult;

void* orig_main;

/* Our fake main() that gets called by __libc_start_main() */
int main_hook(int argc, char **argv, char **envp)
{
    if(argc != 3) {
        usage();
        exit(1);
    }

    printf("Finding %s...", argv[1]);
    fflush(stdout);
    void* target = orig_main + strtol(argv[1], NULL, 0);
    if(!target) {
        fprintf(stderr, "\nCould not find %s!\n", argv[1]);
        exit(1);
    }
    printf("Done!\n");
    printf("main: %p\ntarget: %p\n", orig_main, target);

    fuzz_target = (uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))target;

    FILE* f = fopen(argv[2], "rb");
    fread(&fuzzResult.preexecution.rdi, sizeof(fuzzResult.preexecution.rdi), 1, f);
    fread(&fuzzResult.preexecution.rsi, sizeof(fuzzResult.preexecution.rsi), 1, f);
    fread(&fuzzResult.preexecution.rdx, sizeof(fuzzResult.preexecution.rdx), 1, f);
    fread(&fuzzResult.preexecution.rcx, sizeof(fuzzResult.preexecution.rcx), 1, f);
    fread(&fuzzResult.preexecution.r8, sizeof(fuzzResult.preexecution.r8), 1, f);
    fread(&fuzzResult.preexecution.r9, sizeof(fuzzResult.preexecution.r9), 1, f);
    fclose(f);

//    printf("Waiting for debugger to attach %d\n", getpid());
//    volatile int i = 0;
//    while(i == 0) {
//        usleep(100000);
//    }

    fuzzResult.postexecution.rax =
            fuzz_target(fuzzResult.preexecution.rdi, fuzzResult.preexecution.rsi,
                fuzzResult.preexecution.rdx, fuzzResult.preexecution.rcx,
                fuzzResult.preexecution.r8, fuzzResult.preexecution.r9);

    register uint64_t rdi asm("rdi");
    register uint64_t rsi asm("rsi");
    register uint64_t rdx asm("rdx");
    register uint64_t rcx asm("rcx");
    register uint64_t r8 asm("r8");
    register uint64_t r9 asm("r9");

    fuzzResult.postexecution.rdi = rdi;
    fuzzResult.postexecution.rsi = rsi;
    fuzzResult.postexecution.rdx = rdx;
    fuzzResult.postexecution.rcx = rcx;
    fuzzResult.postexecution.r8 = r8;
    fuzzResult.postexecution.r9 = r9;

    FILE* out = fopen("fuzz-results.bin", "wab");
    fwrite(&fuzzResult, sizeof(fuzzResult), 1, out);
    fclose(out);
    return (int)fuzzResult.postexecution.rax;
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
        void *stack_end)
{
    orig_main = main;

    /* Find the real __libc_start_main()... */
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

    /* afl-fuzz sets argv[0] to be qemu, so ignore that too */
    if(strstr(argv[0], "afl-fuzz") == NULL &&
        strstr(argv[0], "qemu") == NULL) {
        /* ... and call it with our custom main function */
        return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
    } else {
        return orig(orig_main, argc, argv, init, fini, rtld_fini, stack_end);
    }
}