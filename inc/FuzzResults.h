//
// Created by derrick on 12/6/18.
//

#ifndef FOSBIN_FUZZRESULTS_H
#define FOSBIN_FUZZRESULTS_H

struct X86FuzzingContext {
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long rcx;
    unsigned long r8;
    unsigned long r9;
};

struct FuzzingResult {
    uintptr_t executable_offset;
    struct X86FuzzingContext preexecution;
    struct X86FuzzingContext postexecution;
};

#endif //FOSBIN_FUZZRESULTS_H
