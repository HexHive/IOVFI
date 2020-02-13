//
// Created by derrick on 12/20/18.
//

#ifndef FOSBIN_FOSBIN_ZERGLING_H
#define FOSBIN_FOSBIN_ZERGLING_H

#include "pin.H"
#include "X86Context.h"
#include "AllocatedArea.h"
#include "FBZergContext.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#define SHARED_LIBRARY_LOADER   "fb-load"

struct TaintedObject {
    BOOL isRegister;
    union {
        REG reg;
        ADDRINT addr;
    };
};

VOID displayCurrentContext(const CONTEXT *ctx, UINT32 sig = 0);

VOID log_message(std::stringstream &message);

VOID log_error(std::stringstream &message);

VOID log_message(const char *message);

VOID log_error(const char *message);

size_t fuzz_strategy(uint8_t *buffer, size_t size);

void track_syscalls(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);

void fini(INT32 code, void *v);

void CallTarget(void *v);

#endif //FOSBIN_FOSBIN_ZERGLING_H
