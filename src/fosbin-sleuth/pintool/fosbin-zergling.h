//
// Created by derrick on 12/20/18.
//

#ifndef FOSBIN_FOSBIN_ZERGLING_H
#define FOSBIN_FOSBIN_ZERGLING_H

#include <cstdlib>
#include <sys/mman.h>
#include "pin.H"

#define DEFAULT_ALLOCATION_SIZE 4096
#define SHARED_LIBRARY_LOADER   "fb-load"

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

class ExecutionInfo {
public:
    ExecutionInfo();

    ~ExecutionInfo();

    friend std::ostream &operator<<(std::ostream &out, const ExecutionInfo &info);

    void add_function(const std::string &name);

    void reset();

protected:
    std::vector <std::string> called_functions;
};

class AllocatedArea {
public:
    AllocatedArea();

    AllocatedArea(const AllocatedArea &aa);

    ~AllocatedArea();

    ADDRINT getAddr() const;

    size_t size() const;

    void reset_non_ptrs(const AllocatedArea &aa);

    void fuzz();

    bool fix_pointer(ADDRINT faulting_addr);

    /* Used to indicate if a memory area is another AllocatedArea */
    static ADDRINT MAGIC_VALUE;

    friend std::ostream &operator<<(std::ostream &out, class AllocatedArea *ctx);

    friend std::istream &operator>>(std::istream &in, class AllocatedArea *ctx);

    AllocatedArea &operator=(const AllocatedArea &orig);

    bool operator==(const AllocatedArea &other) const;

    bool operator!=(const AllocatedArea &other) const;

    AllocatedArea *get_subarea(size_t i) const;

    void prettyPrint(size_t depth) const;

    void prettyPrint(std::ostream &o, size_t depth) const;

protected:
    char *malloc_addr, *lower_guard, *upper_guard;
    std::vector<bool> mem_map;
    std::vector<AllocatedArea *> subareas;

    void copy_allocated_area(const AllocatedArea &orig);

    void allocate_area(size_t size);

    void unmap_guard_pages();

    void setup_for_round(bool fuzz);
};

class FBZergContext {
public:
    FBZergContext();

    ~FBZergContext();

    friend std::ostream &operator<<(std::ostream &out, const FBZergContext &ctx);

    friend std::istream &operator>>(std::istream &in, FBZergContext &ctx);

    CONTEXT *operator>>(CONTEXT *ctx) const;

    FBZergContext &operator<<(CONTEXT *ctx);

    FBZergContext &operator=(const FBZergContext &orig);

    bool operator==(const FBZergContext &ctx) const;

    bool operator!=(const FBZergContext &ctx) const;

    void add(REG reg, AllocatedArea *aa);

    void add(REG reg, ADDRINT value);

    AllocatedArea *find_allocated_area(REG reg) const;

    const static REG argument_regs[];

    const static REG return_reg;

    ADDRINT get_value(REG reg) const;

    void prettyPrint() const;

    void prettyPrint(std::ostream &s) const;

    void reset_non_ptrs(const FBZergContext &ctx);

    bool return_is_ptr() const;

protected:
    std::map <REG, ADDRINT> values;
    std::map<REG, AllocatedArea *> pointer_registers;
    char return_value;

private:
    bool return_values_equal(const FBZergContext &ctx) const;

    int64_t sign_extend(int64_t orig) const;
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

VOID log_message(std::stringstream &message);

VOID log_error(std::stringstream &message);

VOID log_message(const char *message);

VOID log_error(const char *message);

size_t fuzz_strategy(uint8_t *buffer, size_t size);

void output_context(std::istream &in);

#include "PinLogger.cpp"
#include "X86Context.cpp"
#include "AllocatedArea.cpp"
#include "FBZergContext.cpp"
#include "ContextReader.cpp"
#include "ExecutionInfo.cpp"

#include "ZergCommand.h"
#include "ZergCommandServer.h"

#endif //FOSBIN_FOSBIN_ZERGLING_H
