//
// Created by derrick on 12/4/18.
//
#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <csignal>
#include <cstdlib>
#include <vector>
#include <limits.h>
#include "FuzzResults.h"
#include "fosbin-zergling.h"

#define USER_MSG_TYPE   1000

CONTEXT snapshot;
//CONTEXT preexecution;

KNOB <ADDRINT> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "target", "0", "The target address of the fuzzing target");
KNOB <uint32_t> FuzzCount(KNOB_MODE_WRITEONCE, "pintool", "fuzz-count", "4", "The number of times to fuzz a target");
KNOB <uint32_t> FuzzTime(KNOB_MODE_WRITEONCE, "pintool", "fuzz-time", "0",
                         "The number of minutes to fuzz. Ignores fuzz-count if greater than 0.");
KNOB <uint64_t> MaxInstructions(KNOB_MODE_WRITEONCE, "pintool", "ins", "1000000",
                                "The max number of instructions to run per fuzzing round");
KNOB <std::string> KnobOutName(KNOB_MODE_WRITEONCE, "pintool", "out", "fosbin-fuzz.log",
                               "The name of the file to write "
                               "logging output");
KNOB <std::string> ContextsToUse(KNOB_MODE_APPEND, "pintool", "contexts", "", "Contexts to use for fuzzing");
KNOB <uint32_t> HardFuzzCount(KNOB_MODE_WRITEONCE, "pintool", "hard-limit", "0",
                              "The most fuzzing rounds regardless of time or segfaults. For debug purposes.");
KNOB <std::string> SharedLibraryFunc(KNOB_MODE_WRITEONCE, "pintool", "shared-func", "",
                                     "Shared library function to fuzz.");
KNOB <uint32_t> PrintToScreen(KNOB_MODE_WRITEONCE, "pintool", "print", "1",
                              "Print log messages to screen along with file");
KNOB <uint32_t> WatchDogTimeout(KNOB_MODE_WRITEONCE, "pintool", "watchdog", "20000", "Watchdog timeout in "
                                                                                     "milliseconds");
KNOB<bool> OnlyOutputContexts(KNOB_MODE_WRITEONCE, "pintool", "only-output", "false", "Only output contexts and exit");

RTN target;
uint32_t fuzz_count, orig_fuzz_count, curr_context_file_num, hard_count;
time_t fuzz_end_time;
TLS_KEY log_key;
FBZergContext preContext;
FBZergContext currentContext;
FBZergContext expectedContext;
uint32_t watchdogtime;

std::string shared_library_name;

std::ofstream infofile;
std::ifstream contextFile;
std::vector<struct X86Context> fuzzing_run;
bool fuzzing_started = false;

uint64_t inputContextPassed, totalInputContextsPassed;
uint64_t inputContextFailed, totalInputContextsFailed;

INT32 usage() {
    std::cerr << "FOSBin Zergling -- Causing Havoc in small places" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

inline BOOL timed_fuzz() { return FuzzTime.Value() > 0; }

VOID log_message(std::stringstream &message) {
    if (infofile.is_open()) {
        infofile << message.str() << std::endl;
    }
    if (PrintToScreen.Value()) {
        std::cout << message.str() << std::endl;
    }
    message.clear();
}

VOID log_error(std::stringstream &message) {
    if (infofile.is_open()) {
        infofile << message.str() << std::endl;
    }
    if (PrintToScreen.Value()) {
        std::cout << message.str() << std::endl;
    }
    PIN_WriteErrorMessage(message.str().c_str(), USER_MSG_TYPE, PIN_ERR_FATAL, 0);
}

VOID log_message(const char *message) {
    std::stringstream ss;
    ss << message << std::endl;
    log_message(ss);
}

VOID log_error(const char *message) {
    std::stringstream ss;
    ss << message << std::endl;
    log_error(ss);
}

INS INS_FindByAddress(ADDRINT addr) {
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(addr);
    if (!RTN_Valid(rtn)) {
        return INS_Invalid();
    }

    INS ret = INS_Invalid();
    RTN_Open(rtn);
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        if (INS_Address(ins) == addr) {
            ret = ins;
            break;
        }
    }
    RTN_Close(rtn);
    PIN_UnlockClient();
    return ret;
}

VOID read_new_context() {

    if (contextFile && contextFile.is_open() && contextFile.peek() == EOF) {
//        std::cout << "Closing contextFile" << std::endl;
        contextFile.close();
//        std::cout << "contextFile closed" << std::endl;
        curr_context_file_num++;
    }

    if (curr_context_file_num >= ContextsToUse.NumberOfValues()) {
        return;
    }

//    std::cout << "Reading new context" << std::endl;
    if ((!contextFile || !contextFile.is_open()) && curr_context_file_num < ContextsToUse.NumberOfValues()) {
        std::stringstream ss;
        ss << "Opening " << ContextsToUse.Value(curr_context_file_num);
        log_message(ss);
        contextFile.open(ContextsToUse.Value(curr_context_file_num).c_str(), ios::in | ios::binary);
        inputContextFailed = 0;
        inputContextPassed = 0;
    }

    contextFile >> preContext;
//    log_message("preContext:");
//    preContext.prettyPrint();
//    std::cout << "Read precontext" << std::endl;
    contextFile >> expectedContext;
//    log_message("expectedContext:");
//    expectedContext.prettyPrint();
//    std::cout << "Read expectedcontext" << std::endl;
//    std::cout << "Done reading context" << std::endl;
}

VOID reset_to_context(CONTEXT *ctx, bool readNewContext) {
//    fuzz_count++;
//    std::cout << "fuzz_count = " << std::dec << fuzz_count << " orig_fuzz_count = " << orig_fuzz_count << std::endl;

    if (HardFuzzCount.Value() > 0 && hard_count++ >= HardFuzzCount.Value()) {
        std::stringstream ss;
        ss << "Hit hard limit of " << std::dec << hard_count - 1 << std::endl;
        log_message(ss);
        PIN_ExitApplication(0);
    }

    if (curr_context_file_num < ContextsToUse.NumberOfValues() && readNewContext) {
        read_new_context();
    }

    if (!timed_fuzz()) {
//        std::cout << "curr_context_file_num: " << std::dec << curr_context_file_num << std::endl;
//        std::cout << "orig_fuzz_count: " << orig_fuzz_count << std::endl;
        if (curr_context_file_num >= ContextsToUse.NumberOfValues() && orig_fuzz_count >= FuzzCount.Value()) {
            std::stringstream ss;
            ss << "Stopping fuzzing at " << std::dec << orig_fuzz_count << " of " << FuzzCount.Value()
               << std::endl;
            log_message(ss);
            PIN_ExitApplication(0);
        }
    } else {
        if (time(NULL) >= fuzz_end_time) {
            std::stringstream ss;
            ss << "Stopping fuzzing after " << std::dec << FuzzTime.Value() << " minute"
               << (FuzzTime.Value() > 1 ? "s" : "") << std::endl;
            ss << "Total fuzzing iterations: " << std::dec << fuzz_count - 1 << std::endl;
            log_message(ss);
            PIN_ExitApplication(0);
        }
    }

    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, RTN_Address(target));
    fuzzing_run.clear();
}

VOID reset_context(CONTEXT *ctx) {
    reset_to_context(ctx, true);
}

VOID reset_to_preexecution(CONTEXT *ctx) {
    reset_to_context(ctx, false);
}

uint64_t gen_random() {
    return ((((ADDRINT) rand() << 0) & 0x000000000000FFFFull) |
            (((ADDRINT) rand() << 16) & 0x00000000FFFF0000ull) |
            (((ADDRINT) rand() << 32) & 0x0000FFFF00000000ull) |
            (((ADDRINT) rand() << 48) & 0xFFFF000000000000ull)
    );
}

uint8_t *find_byte_at_random_offset(uint8_t *buffer, size_t buffer_size, size_t write_size) {
    uint64_t offset = 0;
    uint8_t *result;
    if (buffer + write_size >= buffer + buffer_size) {
        return buffer;
    }
    do {
//        std::cout << "Finding random byte between " << std::hex << (ADDRINT) buffer << " and "
//                  << (ADDRINT)(buffer + buffer_size) << " to fit a write_size of " << std::dec << write_size
//                  << std::endl;
        offset = gen_random() % buffer_size;
        result = buffer + offset;
    } while (!(result + write_size <= buffer + buffer_size));
//    std::cout << "Result = " << std::hex << (ADDRINT)result << std::endl;
    return result;
}

size_t flip_bit_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "flip_bit_at_random_offset" << std::endl;
    int bit_to_flip = rand() % CHAR_BIT;
    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(uint8_t));

    *(loc) ^= (1u << bit_to_flip);
    return sizeof(uint8_t);
}

size_t set_interesting_byte_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "set_interesting_byte_at_random_offset" << std::endl;

    int8_t interestingvalues[] = {0, -1, 1, CHAR_MIN, CHAR_MAX};

    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(int8_t));
    int8_t value = interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int8_t))];
    *loc = (uint8_t) value;
    return sizeof(int8_t);
}

size_t set_interesting_word_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "set_interesting_word_at_random_offset" << std::endl;

    int32_t interestingvalues[] = {0, -1, 1, INT_MIN, INT_MAX};
    if (size < sizeof(int32_t)) {
        return set_interesting_byte_at_random_offset(buffer, size);
    }

    int32_t *loc = (int32_t *) find_byte_at_random_offset(buffer, size, sizeof(int32_t));
    int32_t value = interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int32_t))];
    *loc = value;
    return sizeof(uint32_t);
}

size_t set_interesting_dword_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "set_interesting_dword_at_random_offset" << std::endl;

    if (size < sizeof(int64_t)) {
        return set_interesting_word_at_random_offset(buffer, size);
    }

    int64_t interestingvalues[] = {0, -1, 1, LONG_MIN, LONG_MAX};
    int64_t value = interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int64_t))];
    int64_t *loc = (int64_t *) find_byte_at_random_offset(buffer, size, sizeof(int64_t));
    *loc = value;
    return sizeof(uint64_t);
}

size_t inc_random_byte_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "inc_random_byte_at_random_offset" << std::endl;

    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(int8_t));
    *loc += 1;
    return sizeof(int8_t);
}

size_t inc_random_word_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "inc_random_word_at_random_offset" << std::endl;

    int32_t *loc = (int32_t *) find_byte_at_random_offset(buffer, size, sizeof(int32_t));
    *loc += 1;
    return sizeof(int32_t);
}

size_t inc_random_dword_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "inc_random_dword_at_random_offset" << std::endl;

    int64_t *loc = (int64_t *) find_byte_at_random_offset(buffer, size, sizeof(int64_t));
    *loc += 1;
    return sizeof(int64_t);
}

size_t set_random_byte_at_random_offset(uint8_t *buffer, size_t size) {
//    std::cout << "set_random_byte_at_random_offset" << std::endl;

    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(uint8_t));
    uint8_t value = (uint8_t) rand();
    *loc = value;
    return sizeof(uint8_t);
}

size_t set_random_word_at_random_offset(uint8_t *buffer, size_t size) {
    if (size < sizeof(uint32_t)) {
        return set_random_byte_at_random_offset(buffer, size);
    }

    uint32_t *loc = (uint32_t *) find_byte_at_random_offset(buffer, size, sizeof(uint32_t));
    *loc = (uint32_t) gen_random();
    return sizeof(uint32_t);
}

size_t set_random_dword_at_random_offset(uint8_t *buffer, size_t size) {
    if (size < sizeof(uint64_t)) {
        return set_random_word_at_random_offset(buffer, size);
    }

    uint64_t *loc = (uint64_t *) find_byte_at_random_offset(buffer, size, sizeof(uint64_t));
    *loc = gen_random();
    return sizeof(uint64_t);
}

size_t fuzz_strategy(uint8_t *buffer, size_t size) {
    int choice = rand() % 10;
    if (choice == 0) {
        return flip_bit_at_random_offset(buffer, size);
    } else if (choice == 1) {
        return set_interesting_byte_at_random_offset(buffer, size);
    } else if (choice == 2) {
        return set_interesting_word_at_random_offset(buffer, size);
    } else if (choice == 3) {
        return set_interesting_dword_at_random_offset(buffer, size);
    } else if (choice == 4) {
        return inc_random_byte_at_random_offset(buffer, size);
    } else if (choice == 5) {
        return inc_random_word_at_random_offset(buffer, size);
    } else if (choice == 6) {
        return inc_random_dword_at_random_offset(buffer, size);
    } else if (choice == 7) {
        return set_random_byte_at_random_offset(buffer, size);
    } else if (choice == 8) {
        return set_random_word_at_random_offset(buffer, size);
    } else if (choice == 9) {
        return set_random_dword_at_random_offset(buffer, size);
    }

    return 0;
}

VOID fuzz_registers(CONTEXT *ctx) {
//    std::cout << "Fuzzing registers" << std::endl;
    for (REG reg : FBZergContext::argument_regs) {
        AllocatedArea *aa = preContext.find_allocated_area(reg);
        if (aa == nullptr) {
            ADDRINT value = preContext.get_value(reg);
            fuzz_strategy((uint8_t * ) & value, sizeof(value));
            preContext.add(reg, value);
        } else {
//            std::cout << "Fuzzing allocated area" << std::endl;
            aa->fuzz();
        }
//        std::cout << "Done fuzzing register " << REG_StringShort(reg) << std::endl;
    }
}

void output_context(const FBZergContext &ctx) {
    std::vector < AllocatedArea * > allocs;
    PinLogger &logger = *(static_cast<PinLogger *>(PIN_GetThreadData(log_key, PIN_ThreadId())));
    logger << ctx;
}

VOID start_fuzz_round(CONTEXT *ctx) {
    reset_context(ctx);
    if (curr_context_file_num >= ContextsToUse.NumberOfValues()) {
        fuzz_registers(ctx);
    }
    currentContext = preContext;
//    std::cout << "==========================" << std::endl;
//    preContext.prettyPrint();
//    std::cout << "==========================" << std::endl;
//    std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
//    currentContext.prettyPrint();
//    std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
    currentContext >> ctx;
//    currentContext.prettyPrint();
//    displayCurrentContext(ctx);
    std::stringstream ss;
    ss << "Starting round " << std::dec << (fuzz_count + 1) << std::endl;
    log_message(ss);
    PIN_ExecuteAt(ctx);
}

VOID record_current_context(ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx,
                            ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11,
                            ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15,
                            ADDRINT rdi, ADDRINT rsi, ADDRINT rip, ADDRINT rbp
) {
//    std::cout << "Recording context " << std::dec << fuzzing_run.size() << std::endl;
//    std::cout << INS_Disassemble(INS_FindByAddress(rip)) << std::endl;

    struct X86Context tmp = {rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15, rip, rbp};
    fuzzing_run.push_back(tmp);
//    tmp.prettyPrint(std::cout);
//    int64_t diff = MaxInstructions.Value() - fuzzing_run.size();
//    std::cout << std::dec << diff << std::endl;
    if (fuzzing_run.size() > MaxInstructions.Value()) {
        std::stringstream ss;
        ss << "Too many instructions! Starting Over...";
        log_message(ss);
        start_fuzz_round(&snapshot);
    }
}

VOID trace_execution(TRACE trace, VOID *v) {
//    if (TRACE_Rtn(trace) == target) {
    if (fuzzing_started) {
        for (BBL b = TRACE_BblHead(trace); BBL_Valid(b); b = BBL_Next(b)) {
            for (INS ins = BBL_InsHead(b); INS_Valid(ins); ins = INS_Next(ins)) {
                if (RTN_Valid(INS_Rtn(ins)) && SEC_Name(RTN_Sec(INS_Rtn(ins))) == ".text") {
//                    if (!INS_Valid(INS_FindByAddress(INS_Address(ins)))) {
//                        std::cout << "Invalid instruction at 0x" << INS_Address(ins) << ": " << INS_Disassemble(ins)
//                                  << std::endl;
//                    }
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) record_current_context,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_RAX,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_RBX,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_RCX,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_RDX,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R8,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R9,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R10,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R11,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R12,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R13,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R14,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_R15,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_RDI,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_RSI,
                                   IARG_INST_PTR,
                                   IARG_REG_VALUE, LEVEL_BASE::REG_RBP,
                                   IARG_END);
                }
            }
        }
    }
//    }
}

VOID end_fuzzing_round(CONTEXT *ctx, THREADID tid) {
    std::stringstream ss;
    ss << "Ending fuzzing round after executing " << std::dec << fuzzing_run.size() << " instructions";
    log_message(ss);
//    std::cout << "Post Execution Current Context addr = 0x" << std::hex << currentContext.find_allocated_area(FBZergContext::argument_regs[0])->getAddr() << std::endl;

//    std::cout << "Outputting precontext" << std::endl;
//    preContext.prettyPrint();
    output_context(preContext);
//    std::cout << "currentContext:" << std::endl;
//    displayCurrentContext(ctx);
    currentContext << ctx;
//    std::cout << "Outputting currentContext" << std::endl;
//    currentContext.prettyPrint();
    output_context(currentContext);

    if (contextFile && contextFile.is_open()) {
        if (currentContext == expectedContext) {
            inputContextPassed++;
            totalInputContextsPassed++;
        } else {
            inputContextFailed++;
            totalInputContextsFailed++;
        }
    }

    fuzz_count++;
    if (curr_context_file_num >= ContextsToUse.NumberOfValues()) {
        orig_fuzz_count++;
    }
    start_fuzz_round(ctx);
}

VOID begin_fuzzing(CONTEXT *ctx, THREADID tid) {
    std::stringstream ss;
    ss << "Beginning to fuzz";
    log_message(ss);
    fuzzing_started = true;
    PIN_SaveContext(ctx, &snapshot);
    for (REG reg : FBZergContext::argument_regs) {
        preContext.add(reg, (ADDRINT) 0);
    }
    start_fuzz_round(ctx);
}

EXCEPT_HANDLING_RESULT globalSegfaultHandler(THREADID tid, EXCEPTION_INFO *exceptionInfo, PHYSICAL_CONTEXT
*physContext, VOID *v) {
    std::stringstream ss;
    ss << "Global segfault handler called: " << PIN_ExceptionToString(exceptionInfo);
    log_error(ss);
    PIN_SetExceptionAddress(exceptionInfo, RTN_Address(target));
    PIN_RaiseException(&snapshot, tid, exceptionInfo);
    return EHR_HANDLED;
}

VOID displayCurrentContext(const CONTEXT *ctx, UINT32 sig) {
    std::stringstream ss;
    ss << "[" << (sig != SIGSEGV ? "CONTEXT" : "SIGSEGV")
       << "]=----------------------------------------------------------" << std::endl;
    ss << std::hex << std::internal << std::setfill('0')
       << "RAX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX) << " "
       << "RBX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX) << " "
       << "RCX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX) << std::endl
       << "RDX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX) << " "
       << "RDI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI) << " "
       << "RSI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI) << std::endl
       << "RBP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP) << " "
       << "RSP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP) << " "
       << "RIP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP) << std::endl;
    ss << "+-------------------------------------------------------------------" << std::endl;
    log_message(ss);
}

ADDRINT compute_effective_address(REG base, REG idx, UINT32 scale, ADDRDELTA displacement, struct X86Context &ctx) {
    if (!REG_valid(base)) {
        std::stringstream ss;
        ss << "Invalid base" << std::endl;
        return 0;
    }

    ADDRINT ret = displacement + ctx.get_reg_value(base) + ctx.get_reg_value(idx) * scale;
    return ret;
}

ADDRINT compute_effective_address(INS ins, struct X86Context &ctx, UINT32 operand = 0) {
    REG base = INS_OperandMemoryBaseReg(ins, operand);
    REG idx = INS_OperandMemoryIndexReg(ins, operand);
    UINT32 scale = INS_OperandMemoryScale(ins, operand);
    ADDRDELTA displacement = INS_OperandMemoryDisplacement(ins, operand);
//    std::cout << INS_Disassemble(ins) << std::endl;
//    std::cout << "Base: " << REG_StringShort(base)
//        << " Idx: " << REG_StringShort(idx)
//        << " Scale: 0x" << std::hex << scale
//        << " Disp: 0x" << displacement << std::endl;
//
//    ctx.prettyPrint(std::cout);

    ADDRINT ret = compute_effective_address(base, idx, scale, displacement, ctx);
//    std::cout << "ret: " << ret << std::endl;
    return ret;
}

BOOL isTainted(REG reg, std::vector<struct TaintedObject> &taintedObjs) {
    for (struct TaintedObject &to : taintedObjs) {
        if (to.isRegister && REG_StringShort(to.reg) == REG_StringShort(reg)) {
            return true;
        }
    }
    return false;
}

BOOL isTainted(ADDRINT addr, std::vector<struct TaintedObject> &taintedObjs) {
    for (struct TaintedObject &to : taintedObjs) {
        if (!to.isRegister && to.addr == addr) {
            return true;
        }
    }
    return false;
}

VOID remove_taint(REG reg, std::vector<struct TaintedObject> &taintedObjs) {
//    std::stringstream ss;
//    ss << "\tRemoving taint from " << REG_StringShort(reg) << std::endl;
//    log_message(ss);
    for (std::vector<struct TaintedObject>::iterator it = taintedObjs.begin(); it != taintedObjs.end(); ++it) {
        struct TaintedObject &to = *it;
        if (to.isRegister && REG_StringShort(to.reg) == REG_StringShort(reg)) {
            taintedObjs.erase(it);
            return;
        }
    }
}

VOID add_taint(REG reg, std::vector<struct TaintedObject> &taintedObjs) {
//    std::stringstream ss;
//    ss << "\tAdding taint to " << REG_StringShort(reg) << std::endl;
//    log_message(ss);
    struct TaintedObject to;
    to.isRegister = true;
    to.reg = reg;
    taintedObjs.push_back(to);
}

VOID remove_taint(ADDRINT addr, std::vector<struct TaintedObject> &taintedObjs) {
//    std::stringstream ss;
//    ss << "\tRemoving taint from 0x" << std::hex << addr << std::endl;
//    log_message(ss);
    for (std::vector<struct TaintedObject>::iterator it = taintedObjs.begin(); it != taintedObjs.end(); ++it) {
        struct TaintedObject &to = *it;
        if (!to.isRegister && addr == to.addr) {
            taintedObjs.erase(it);
            return;
        }
    }
}

VOID add_taint(ADDRINT addr, std::vector<struct TaintedObject> &taintedObjs) {
//    std::stringstream ss;
//    ss << "\tAdding taint to 0x" << std::hex << addr << std::endl;
//    log_message(ss);
    struct TaintedObject to;
    to.isRegister = false;
    to.addr = addr;
    taintedObjs.push_back(to);
}

BOOL inline is_rbp(REG reg) {
    return LEVEL_BASE::REG_RBP == reg;
}

BOOL create_allocated_area(struct TaintedObject &to, ADDRINT faulting_address) {
    if (to.isRegister) {
        /* Fuzzing is done with currentContext */
        AllocatedArea *aa = currentContext.find_allocated_area(to.reg);
        if (aa == nullptr) {
            aa = new AllocatedArea();
//            std::cout << "Creating allocated area for "
//                      << REG_StringShort(to.reg) << " at 0x"
//                      << std::hex << aa->getAddr() << std::endl;
            preContext.add(to.reg, aa);
            currentContext = preContext;
        } else {
            if (!aa->fix_pointer(faulting_address)) {
                std::stringstream ss;
                ss << "Could not fix pointer in register " << REG_StringShort(to.reg) << std::endl;
                log_error(ss);
            }
            AllocatedArea *tmp = preContext.find_allocated_area(to.reg);
            aa->reset_non_ptrs(*tmp);
//            currentContext.prettyPrint();
            *tmp = *aa;
            preContext.add(to.reg, tmp);
//            preContext.prettyPrint();
//            std::cout << "Fixed pointer" << std::endl;
        }
    } else {
        IMG img = IMG_FindByAddress(to.addr);
        SEC s = SEC_Invalid();
        for (s = IMG_SecHead(img); SEC_Valid(s); s = SEC_Next(s)) {
            ADDRINT sec_start = SEC_Address(s);
            ADDRINT sec_end = sec_start + SEC_Size(s);
            if (to.addr >= sec_start && to.addr < sec_end) {
                break;
            }
        }
        std::stringstream ss;
        ss << "Cannot taint non-registers. ";
        if (SEC_Valid(s)) {
            ss << "Address 0x" << std::hex << to.addr << " is in section " << SEC_Name(s) << "of image " << IMG_Name
                    (img);
        } else if (IMG_Valid(img)) {
            ss << "Address 0x" << std::hex << to.addr << " could not be found in a section but is in image " <<
               IMG_Name(img);
        } else {
            ss << "Address 0x" << std::hex << to.addr << " could not be found in an image";
        }
        log_message(ss);
        return false;
    }

//    preContext.prettyPrint();
    return true;
}

BOOL catchSignal(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
//    std::cout << PIN_ExceptionToString(pExceptInfo) << std::endl;
//    std::cout << "Fuzzing run size: " << std::dec << fuzzing_run.size() << std::endl;
//    displayCurrentContext(ctx);
//    currentContext.prettyPrint();
    if (curr_context_file_num < ContextsToUse.NumberOfValues()) {
        inputContextFailed++;
        totalInputContextsFailed++;
//        fuzz_count--;
//        if (curr_context_file_num >= ContextsToUse.NumberOfValues()) {
//            orig_fuzz_count--;
//        }
        reset_context(ctx);
        currentContext = preContext;
        log_message("Input context failed...trying a new one");
        goto finish;
    }

    {
        std::stringstream log;
        std::vector<struct TaintedObject> taintedObjs;
        REG taint_source = REG_INVALID();
        for (std::vector<struct X86Context>::reverse_iterator it = fuzzing_run.rbegin();
             it != fuzzing_run.rend(); ++it) {
            struct X86Context &c = *it;
            INS ins = INS_FindByAddress(c.rip);
            if (!INS_Valid(ins)) {
                std::stringstream ss;
                ss << "Could not find failing instruction at 0x" << std::hex << c.rip << std::endl;
                log_error(ss);
            }

//            log << RTN_Name(RTN_FindByAddress(INS_Address(ins)))
//                      << "(0x" << std::hex << INS_Address(ins) << "): " << INS_Disassemble(ins) << std::endl;
//            log << "\tINS_IsMemoryRead: " << (INS_IsMemoryRead(ins) ? "true" : "false") << std::endl;
//            log << "\tINS_HasMemoryRead2: " << (INS_HasMemoryRead2(ins) ? "true" : "false") << std::endl;
//            log << "\tINS_IsMemoryWrite: " << (INS_IsMemoryWrite(ins) ? "true" : "false") << std::endl;
//            log << "\tCategory: " << CATEGORY_StringShort(INS_Category(ins)) << std::endl;
//            log << "\tINS_MaxNumRRegs: " << INS_MaxNumRRegs(ins) << std::endl;
//            for (unsigned int i = 0; i < INS_MaxNumRRegs(ins); i++) {
//                log << "\t\t" << REG_StringShort(INS_RegR(ins, i)) << std::endl;
//            }
//            log << "\tINS_MaxNumWRegs: " << INS_MaxNumWRegs(ins) << std::endl;
//            for (unsigned int i = 0; i < INS_MaxNumWRegs(ins); i++) {
//                log << "\t\t" << REG_StringShort(INS_RegW(ins, i)) << std::endl;
//            }
//            log_message(log);

            if (it == fuzzing_run.rbegin()) {
                taint_source = REG_INVALID();
                for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
                    REG possible_source = INS_OperandMemoryBaseReg(ins, i);
//                    std::cout << std::dec << i << ": " << REG_StringShort(possible_source) << std::endl;
                    if (REG_valid(possible_source) && preContext.find_allocated_area(possible_source) == nullptr) {
                        taint_source = possible_source;
                        break;
                    }
                }

                if (!REG_valid(taint_source)) {
                    std::stringstream ss;
                    ss << "Could not find valid base register for instruction: " << INS_Disassemble(ins);
                    log_error(ss);
                }
                add_taint(taint_source, taintedObjs);
//                continue;
            }

            if (INS_IsMov(ins) || INS_IsLea(ins) || INS_IsMemoryWrite(ins)) {
                REG wreg = REG_INVALID();
                ADDRINT writeAddr = 0;
                if (INS_OperandIsReg(ins, 0)) {
                    wreg = INS_OperandReg(ins, 0);
//                    log << "\tWrite register is " << REG_StringShort(wreg) << std::endl;
                } else if (INS_OperandIsMemory(ins, 0)) {
                    wreg = INS_OperandMemoryBaseReg(ins, 0);
                    if (!REG_valid(wreg)) {
                        writeAddr = compute_effective_address(ins, c);
                    }
                } else {
                    std::stringstream ss;
                    ss << "Write operand is not memory or register: " << INS_Disassemble(ins);
//                    log_error(ss);
                    continue;
                }
//                log_message(log);

                if (REG_valid(wreg) && !isTainted(wreg, taintedObjs)) {
//                    log << "\tWrite register is not tainted" << std::endl;
//                    log_message(log);
                    continue;
                } else if (!REG_valid(wreg) && !isTainted(writeAddr, taintedObjs)) {
//                    log << "\tWrite address is not tainted" << std::endl;
//                    log_message(log);
                    continue;
                }

                REG rreg = REG_INVALID();
                ADDRINT readAddr = 0;

                if (INS_OperandIsReg(ins, 1)) {
                    rreg = INS_OperandReg(ins, 1);
//                    log << "\tRead register is " << REG_StringShort(rreg) << std::endl;
                } else if (INS_OperandIsMemory(ins, 1)) {
                    rreg = INS_OperandMemoryBaseReg(ins, 1);
                    if (!REG_valid(rreg)) {
                        readAddr = compute_effective_address(ins, c, 1);
                    }
                } else if (INS_OperandIsImmediate(ins, 1)) {
                    continue;
                } else if (INS_OperandIsAddressGenerator(ins, 1) || INS_MemoryOperandIsRead(ins, 1)) {
                    rreg = INS_OperandMemoryBaseReg(ins, 1);
//                    log << "\tRead register is " << REG_StringShort(rreg) << std::endl;
                } else {
                    std::stringstream ss;
                    ss << "Read operand is not a register, memory address, or immediate: " << INS_Disassemble(ins) <<
                       std::endl;
                    ss << "OperandIsAddressGenerator: " << INS_OperandIsAddressGenerator(ins, 1) << std::endl;
                    ss << "OperandIsFixedMemop: " << INS_OperandIsFixedMemop(ins, 1) << std::endl;
                    ss << "OperandIsImplicit: " << INS_OperandIsImplicit(ins, 1) << std::endl;
                    ss << "Base register: " << REG_StringShort(INS_MemoryBaseReg(ins)) << std::endl;
                    ss << "Category: " << CATEGORY_StringShort(INS_Category(ins)) << std::endl;
                    for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
                        ss << "Operand " << std::dec << i << " reg: " << REG_StringShort(INS_OperandReg(ins, i)) <<
                           std::endl;
                    }

                    log_message(ss);
                    continue;
                }

//                log_message(log);
                if (REG_valid(wreg)) {
                    if (REG_valid(rreg)) {
                        if (isTainted(wreg, taintedObjs) && !isTainted(rreg, taintedObjs)) {
                            remove_taint(wreg, taintedObjs);
                            add_taint(rreg, taintedObjs);
                        }
                    } else {
                        if (isTainted(wreg, taintedObjs) && !isTainted(readAddr, taintedObjs)) {
                            remove_taint(wreg, taintedObjs);
                            add_taint(readAddr, taintedObjs);
                        }
                    }
                } else {
                    if (REG_valid(rreg)) {
                        if (isTainted(writeAddr, taintedObjs) && !isTainted(rreg, taintedObjs)) {
                            remove_taint(wreg, taintedObjs);
                            add_taint(rreg, taintedObjs);
                        }
                    } else {
                        if (isTainted(writeAddr, taintedObjs) && !isTainted(readAddr, taintedObjs)) {
                            remove_taint(wreg, taintedObjs);
                            add_taint(readAddr, taintedObjs);
                        }
                    }
                }
            }
        }

        if (taintedObjs.size() > 0) {
            struct TaintedObject taintedObject = taintedObjs.back();
//            if (taintedObject.isRegister) {
//                log << "Tainted register: " << REG_StringShort(taintedObject.reg) << std::endl;
//            } else {
//                log << "Tainted address: 0x" << std::hex << taintedObject.addr << std::endl;
//            }

            /* Find the last write to the base register to find the address of the bad pointer */
            INS ins = INS_FindByAddress(fuzzing_run.back().rip);
            REG faulting_reg = taint_source;
//            std::cout << "Faulting reg: " << REG_StringShort(faulting_reg) << std::endl;
            ADDRINT faulting_addr = compute_effective_address(ins, fuzzing_run.back(), 1);
            for (std::vector<struct X86Context>::reverse_iterator it = fuzzing_run.rbegin();
                 it != fuzzing_run.rend(); it++) {
                if (it == fuzzing_run.rbegin()) {
                    continue;
                }
                ins = INS_FindByAddress(it->rip);
//            std::cout << INS_Disassemble(ins) << std::endl;
                if (INS_RegWContain(ins, faulting_reg)) {
//                it->prettyPrint(std::cout);
//                    std::cout << "Write instruction: " << INS_Disassemble(ins) << std::endl;
                    faulting_addr = compute_effective_address(ins, *it, 1);
//                    std::cout << "Faulting addr: 0x" << std::hex << faulting_addr << std::endl;
                    break;
                }
            }

            if (!create_allocated_area(taintedObject, faulting_addr)) {
//                for(auto &it : fuzzing_run) {
//                    std::cout << INS_Disassemble(INS_FindByAddress(it.rip)) << std::endl;
//                }
                reset_to_preexecution(ctx);
                fuzz_registers(ctx);
                goto finish;
            }
        } else {
            log_message("Taint analysis failed for the following context: ");
            displayCurrentContext(ctx);
            PIN_ExitApplication(1);
        }

        reset_to_preexecution(ctx);
    }
    finish:

//    preContext.prettyPrint();
//    currentContext.prettyPrint();
    currentContext >> ctx;
//    fuzz_registers(ctx);
//    PIN_SaveContext(ctx, &preexecution);
//    displayCurrentContext(ctx);
    return false;
}

VOID ImageLoad(IMG img, VOID *v) {
    if (!IMG_Valid(img)) {
        return;
    }

//    std::cout << "Image " << IMG_Name(img) << " loaded" << std::endl;

    if (SharedLibraryFunc.Value() == "") {
        if (!IMG_IsMainExecutable(img)) {
            return;
        }
        ADDRINT offset = IMG_LoadOffset(img);
        ADDRINT target_addr = KnobStart.Value() + offset;
        target = RTN_FindByAddress(target_addr);
        if (!RTN_Valid(target)) {
            std::stringstream ss;
            ss << "Could not find target at 0x" << std::hex << target_addr << " (0x" << offset << " + 0x" <<
               KnobStart.Value() << ")" << std::endl;
            log_error(ss);
        }

        ADDRINT main_addr = IMG_Entry(img);
        RTN main = RTN_FindByAddress(main_addr);
        if (RTN_Valid(main)) {
            RTN_Open(main);
            INS_InsertCall(RTN_InsHead(main), IPOINT_BEFORE, (AFUNPTR) begin_fuzzing, IARG_CONTEXT, IARG_THREAD_ID,
                           IARG_END);
            RTN_Close(main);
        } else {
            std::stringstream ss;
            ss << "Could not find main!" << std::endl;
            log_error(ss);
        }

    } else {
        if (IMG_Name(img) == shared_library_name) {
//            std::cout << shared_library_name << " has been loaded" << std::endl;
            bool found = false;
            for (SEC s = IMG_SecHead(img); SEC_Valid(s) && !found; s = SEC_Next(s)) {
                for (RTN f = SEC_RtnHead(s); RTN_Valid(f); f = RTN_Next(f)) {
//                    std::cout << "Found " << RTN_Name(f) << std::endl;
                    if (RTN_Name(f) == SharedLibraryFunc.Value()) {
                        target = f;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
//            std::cerr << "Could not find target " << SharedLibraryFunc.Value() << " in shared library " << SharedLibraryName.Value() << std::endl;
                exit(1);
            } else {
//                std::cout << "Found " << SharedLibraryFunc.Value() << std::endl;
            }
        } else if (!IMG_IsMainExecutable(img)) {
//            std::cout << "Irrelevant image" << std::endl;
            return;
        } else {
            /* The loader program calls dlopen on the shared library, and then immediately returns,
             * so add a call at the return statement to start fuzzing the shared library function
             */
            RTN main = RTN_FindByName(img, "main");
            if (!RTN_Valid(main)) {
                log_error("Invalid main in fb-loader");
            }
            RTN_Open(main);
            std::stringstream ss;
            ss << "Instrumenting loader main...";
            for (INS ins = RTN_InsHead(main); INS_Valid(ins); ins = INS_Next(ins)) {
                if (INS_IsRet(ins)) {
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) begin_fuzzing, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
                }
            }
            ss << "done!";
            log_message(ss);
            RTN_Close(main);
            return;
        }
    }
    std::stringstream ss;
    ss << "Found target: " << RTN_Name(target) << " at 0x" << std::hex << RTN_Address(target) << std::endl;
    ss << "Instrumenting returns...";
    RTN_Open(target);
    for (INS ins = RTN_InsHead(target); INS_Valid(ins); ins = INS_Next(ins)) {
        if (INS_IsRet(ins)) {
//            std::cout << "Adding end_fuzzing_round" << std::endl;

            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) end_fuzzing_round, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
        }
    }
    INS_InsertCall(RTN_InsTail(target), IPOINT_BEFORE, (AFUNPTR) end_fuzzing_round, IARG_CONTEXT, IARG_THREAD_ID,
                   IARG_END);
    RTN_Close(target);
    ss << "done.";
    log_message(ss);
}

VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v) {
    std::string fname;
    if (SharedLibraryFunc.Value() != "") {
        fname = SharedLibraryFunc.Value() + "." + decstr(tid) + ".ctx";
    } else {
        fname = RTN_Name(target) + "." + decstr(tid) + ".ctx";
    }
    PinLogger *logger = new PinLogger(tid, fname);
    PIN_SetThreadData(log_key, logger, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v) {
    VOID *logger_loc = PIN_GetThreadData(log_key, tid);
    if (logger_loc != nullptr) {
//        std::cout << "Deleting logger" << std::endl;
        PinLogger *logger = static_cast<PinLogger *>(logger_loc);
        delete logger;
        PIN_SetThreadData(log_key, nullptr, tid);
    }

    if (ContextsToUse.NumberOfValues() > 0) {
        std::stringstream ss;
        ss << "Input Contexts Passed: " << std::dec << totalInputContextsPassed << std::endl;
        ss << "Input Contexts Failed: " << std::dec << totalInputContextsFailed << std::endl;
        log_message(ss);
    }
}

void initialize_system(int argc, char **argv) {
    std::stringstream ss;
    ss << "Initializing system...";
    srand(time(NULL));
    std::string infoFileName = KnobOutName.Value();
    infofile.open(infoFileName.c_str(), std::ios::out | std::ios::app);

    log_key = PIN_CreateThreadDataKey(0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    fuzz_end_time = time(NULL) + 60 * FuzzTime.Value();

    if (FuzzTime.Value()) {
        watchdogtime = FuzzTime.Value() * 1000 * 60 + 5;
    } else {
        watchdogtime = WatchDogTimeout.Value();
    }

    if (SharedLibraryFunc.Value() != "") {
        if (strstr(argv[argc - 2], SHARED_LIBRARY_LOADER) == NULL) {
            ss << "fb-load must be the program run when fuzzing shared libraries" << std::endl;
            log_error(ss);
        }
        shared_library_name = argv[argc - 1];
        IMG img = IMG_Open(shared_library_name);
        if (!IMG_Valid(img)) {
            ss << "Could not open " << shared_library_name << std::endl;
            log_error(ss);
        }
        bool found = false;
        for (SEC s = IMG_SecHead(img); SEC_Valid(s) && !found; s = SEC_Next(s)) {
            for (RTN f = SEC_RtnHead(s); RTN_Valid(f); f = RTN_Next(f)) {
                if (RTN_Name(f) == SharedLibraryFunc.Value()) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            ss << "Could not find " << SharedLibraryFunc.Value() << " in library " << shared_library_name
               << std::endl;
            IMG_Close(img);
            log_error(ss);
        }

        IMG_Close(img);
    }

    if (ContextsToUse.NumberOfValues() > 0) {
        ss << "Using contexts: " << std::endl;
        for (size_t i = 0; i < ContextsToUse.NumberOfValues(); i++) {
            ss << ContextsToUse.Value(i) << std::endl;
        }
    }
    ss << "done!" << std::endl;
    log_message(ss);
}

VOID watch_dog(void *arg) {
    UINT32 millis = *(UINT32 *) arg;
    PIN_Sleep(millis);
    log_message("Watchdog tripped");
    PIN_ExitProcess(1);
}

int main(int argc, char **argv) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        return usage();
    }

    if (OnlyOutputContexts.Value()) {
        for (size_t i = 0; i < ContextsToUse.NumberOfValues(); i++) {
            contextFile.open(ContextsToUse.Value(i).c_str(), ios::in | ios::binary);
            if (!contextFile) {
                std::cerr << "Could not open " << ContextsToUse.Value(i) << std::endl;
                continue;
            }
            std::cout << "Contexts in " << ContextsToUse.Value(i) << ":" << std::endl;
            while (contextFile.peek() != EOF) {
                output_context(contextFile);
            }
            contextFile.close();
        }
        exit(0);
    }

    if (!KnobStart.Value() && SharedLibraryFunc.Value() == "") {
        return usage();
    }
    std::stringstream ss;
    ss << "Starting Zergling..." << std::endl;
    log_message(ss);
    initialize_system(argc, argv);

    if (!timed_fuzz()) {
        if (SharedLibraryFunc.Value() == "") {
            ss << "Fuzzing 0x" << std::hex << KnobStart.Value() << std::dec << " " << FuzzCount.Value() << " times."
               << std::endl;
        } else {
            ss << "Fuzzing " << SharedLibraryFunc.Value() << " " << FuzzCount.Value() << " times."
               << std::endl;
        }
    } else {
        ss << "Fuzzing 0x" << std::hex << KnobStart.Value() << " for " << std::dec << FuzzTime.Value()
           << " minute" << (FuzzTime.Value() > 1 ? "s" : "") << std::endl;
    }

    log_message(ss);
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    TRACE_AddInstrumentFunction(trace_execution, nullptr);
    PIN_InterceptSignal(SIGSEGV, catchSignal, nullptr);
    PIN_SpawnInternalThread(watch_dog, &watchdogtime, 0, nullptr);
    PIN_StartProgram();

    return 0;
}
