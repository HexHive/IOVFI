//
// Created by derrick on 12/6/18.
//

#ifndef FOSBIN_FUZZRESULTS_H
#define FOSBIN_FUZZRESULTS_H

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

struct X86FuzzingContext {
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t r8;
    uint64_t r9;
    uint64_t rax;
};

struct FuzzingResult {
    uintptr_t executable_offset;
    struct X86FuzzingContext preexecution;
    struct X86FuzzingContext postexecution;
};

#endif //FOSBIN_FUZZRESULTS_H
