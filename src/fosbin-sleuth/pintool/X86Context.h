//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_X86CONTEXT_H
#define FOSBIN_X86CONTEXT_H

#include "pin.H"

struct X86Context {
    ADDRINT rax;
    ADDRINT rbx;
    ADDRINT rcx;
    ADDRINT rdx;
    ADDRINT rdi;
    ADDRINT rsi;
    ADDRINT r8;
    ADDRINT r9;
    ADDRINT r10;
    ADDRINT r11;
    ADDRINT r12;
    ADDRINT r13;
    ADDRINT r14;
    ADDRINT r15;
    ADDRINT rip;
    ADDRINT rbp;

    friend std::ostream &operator<<(std::ostream &out, const struct X86Context &ctx);

    void prettyPrint(std::ostream &out);

    ADDRINT get_reg_value(REG reg);
};

#endif //FOSBIN_X86CONTEXT_H
