//
// Created by derrick on 12/20/18.
//

#ifndef FOSBIN_FOSBIN_ZERGLING_H
#define FOSBIN_FOSBIN_ZERGLING_H

#include <cstdlib>
#include "pin.H"

#define DEFAULT_ALLOCATION_SIZE 512

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

class AllocatedArea {
public:
    AllocatedArea();

    ~AllocatedArea();

    void reset();

    ADDRINT getAddr();

    size_t size();

    void fuzz();

    bool fix_pointer(ADDRINT faulting_addr);

    /* Used to indicate if a memory area is another AllocatedArea */
    static ADDRINT MAGIC_VALUE;

    friend std::ostream &operator<<(std::ostream &out, class AllocatedArea *ctx);

    friend std::istream &operator>>(std::istream &in, class AllocatedArea *ctx);

    AllocatedArea &operator=(const AllocatedArea &orig);

    bool operator==(const AllocatedArea &other) const;

    bool operator!=(const AllocatedArea &other) const;

protected:
    ADDRINT addr;
    std::vector<bool> mem_map;
    std::vector<AllocatedArea *> subareas;

    void setup_for_round(bool fuzz);
};

class FBZergContext {
public:
    FBZergContext();

    ~FBZergContext();

    friend std::ostream &operator<<(std::ostream &out, const FBZergContext &ctx);

    std::istream &operator>>(std::istream &in);

    FBZergContext &operator=(const FBZergContext &orig);

    FBZergContext &operator<<(CONTEXT *ctx);

    bool operator==(const FBZergContext &ctx) const;

    bool operator!=(const FBZergContext &ctx) const;

    void add(REG reg, AllocatedArea *aa);

    void add(REG reg, ADDRINT value);

    AllocatedArea *find_allocated_area(REG reg) const;

    void reset_context(CONTEXT *ctx, const FBZergContext &orig);

    const static REG argument_regs[];

    const static REG return_reg;

    ADDRINT get_value(REG reg) const;
protected:
    std::map <REG, ADDRINT> values;
    std::map<REG, AllocatedArea *> pointer_registers;
};

struct TaintedObject {
    BOOL isRegister;
    union {
        REG reg;
        ADDRINT addr;
    };
};

class PinLogger {
public:
    PinLogger(THREADID tid, std::string fname);

    ~PinLogger();

    VOID DumpBufferToFile(struct X86Context *contexts, UINT64 numElements, THREADID tid);

    std::ostream &operator<<(const AllocatedArea *aa);

    std::ostream &operator<<(ADDRINT addr);

    std::ostream &operator<<(const FBZergContext &ctx);

private:
    std::ofstream _ofile;
};

VOID displayCurrentContext(const CONTEXT *ctx, UINT32 sig = 0);

#include "PinLogger.cpp"
#include "X86Context.cpp"
#include "AllocatedArea.cpp"
#include "FBZergContext.cpp"

#endif //FOSBIN_FOSBIN_ZERGLING_H
