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
#include <unistd.h>
#include "FuzzResults.h"
#include "fosbin-zergling.h"
#include <string.h>
#include <csetjmp>

#define USER_MSG_TYPE   1000

CONTEXT snapshot;

KNOB <std::string> KnobInPipe(KNOB_MODE_WRITEONCE, "pintool", "in-pipe", "", "Filename of in pipe");
KNOB <std::string> KnobOutPipe(KNOB_MODE_WRITEONCE, "pintool", "out-pipe", "", "Filename of out pipe");
KNOB <std::string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "log", "", "/path/to/log");
KNOB <std::string> KnobCmdLogFile(KNOB_MODE_WRITEONCE, "pintool", "cmdlog", "", "/path/to/cmd/log");
KNOB <std::string> KnobRustMain(KNOB_MODE_WRITEONCE, "pintool", "rust", "", "Mangled name of rust main");

RTN target = RTN_Invalid();
IMG target_so = IMG_Invalid();
INS first_ins = INS_Invalid();
uintptr_t first_ins_addr = (uintptr_t) - 1;
uintptr_t last_ins_addr = (uintptr_t) - 1;
FBZergContext preContext;
FBZergContext currentContext;
FBZergContext expectedContext;

std::string shared_library_name;
ExecutionInfo executionInfo;
std::string current_function;
std::set <ADDRINT> syscalls;

UINT32 imgId;

std::vector<struct X86Context> fuzzing_run;
std::ofstream log_out;
uint64_t max_instructions = 1000000;
bool fuzzed_input = false;
bool sent_initial_ready = false;
bool adjusted_stack = false;

ZergCommandServer *cmd_server;
int internal_pipe_in[2];
int internal_pipe_out[2];
int cmd_out;
int cmd_in;
fd_set exe_fd_set_in;
fd_set exe_fd_set_out;
int ctx_count = 0;

void wait_to_start();

void report_failure(zerg_cmd_result_t reason, CONTEXT *ctx = nullptr);

void cleanup(int exitcode) {
    PIN_RemoveInstrumentation();
    if (cmd_server) {
        cmd_server->stop();
        delete cmd_server;
    }
    PIN_ExitApplication(exitcode);
}

INT32 usage() {
    std::cerr << "FOSBin Zergling -- Causing Havoc in small places" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

VOID log_message(std::stringstream &message) {
    if (message.str().empty()) {
        return;
    }

//    if (log_out && log_out.is_open()) {
//        log_out << message.str() << std::endl;
//    } else {
//        std::cout << message.str() << std::endl;
//    }

    message.str(std::string());
}

VOID log_error(std::stringstream &message) {
    log_message(message);
    cleanup(1);
}

VOID log_message(const char *message) {
    std::stringstream ss;
    ss << message;
    log_message(ss);
}

VOID log_error(const char *message) {
    std::stringstream ss;
    ss << message;
    log_error(ss);
}

void log_message(const std::string &message) {
    std::stringstream msg;
    msg << message;
    log_message(msg);
}

void log_error(const std::string &message) {
    std::stringstream msg;
    msg << message;
    log_error(msg);
}

bool is_executable_fbloader(IMG img) {
    const std::string &name = IMG_Name(img);
    return name.find("fb-load") != std::string::npos;
}

ZergMessage *read_from_cmd_server() {
    ZergMessage *result = new ZergMessage();
    if (result->read_from_fd(internal_pipe_in[0]) == 0) {
        log_message("Could not read from command pipe");
    }
    return result;
}

int write_to_cmd_server(ZergMessage &msg) {
    std::stringstream logmsg;
    logmsg << "Writing " << msg.str() << " and " << msg.size() << " bytes to server" << std::endl;
    log_message(logmsg);
    size_t written = msg.write_to_fd(internal_pipe_out[1]);
    if (written == 0) {
        log_message("Could not write to command pipe");
    }
    return written;
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
        offset = gen_random() % buffer_size;
        result = buffer + offset;
    } while (!(result + write_size <= buffer + buffer_size));
    return result;
}

size_t flip_bit_at_random_offset(uint8_t *buffer, size_t size) {
    int bit_to_flip = rand() % CHAR_BIT;
    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(uint8_t));

    *(loc) ^= (1u << bit_to_flip);
    return sizeof(uint8_t);
}

size_t set_interesting_byte_at_random_offset(uint8_t *buffer, size_t size) {
    int8_t interestingvalues[] = {0, -1, 1, CHAR_MIN, CHAR_MAX, 'A', 'a', '?', ' '};

    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(int8_t));
    int8_t value = interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int8_t))];
    *loc = (uint8_t) value;
    return sizeof(int8_t);
}

size_t set_interesting_word_at_random_offset(uint8_t *buffer, size_t size) {
    int32_t interestingvalues[] = {0, -1, 1, INT_MIN, INT_MAX, 'A', 'a', '?', ' '};
    if (size < sizeof(int32_t)) {
        return set_interesting_byte_at_random_offset(buffer, size);
    }

    int32_t *loc = (int32_t *) find_byte_at_random_offset(buffer, size, sizeof(int32_t));
    int32_t value = interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int32_t))];
    *loc = value;
    return sizeof(uint32_t);
}

size_t set_interesting_dword_at_random_offset(uint8_t *buffer, size_t size) {
    if (size < sizeof(int64_t)) {
        return set_interesting_word_at_random_offset(buffer, size);
    }

    int64_t interestingvalues[] = {0, -1, 1, LONG_MIN, LONG_MAX, 'A', 'a', '?', ' '};
    int64_t value = interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int64_t))];
    int64_t *loc = (int64_t *) find_byte_at_random_offset(buffer, size, sizeof(int64_t));
    *loc = value;
    return sizeof(uint64_t);
}

size_t inc_random_byte_at_random_offset(uint8_t *buffer, size_t size) {
    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(int8_t));
    *loc += 1;
    return sizeof(int8_t);
}

size_t inc_random_word_at_random_offset(uint8_t *buffer, size_t size) {
    int32_t *loc = (int32_t *) find_byte_at_random_offset(buffer, size, sizeof(int32_t));
    *loc += 1;
    return sizeof(int32_t);
}

size_t inc_random_dword_at_random_offset(uint8_t *buffer, size_t size) {
    int64_t *loc = (int64_t *) find_byte_at_random_offset(buffer, size, sizeof(int64_t));
    *loc += 1;
    return sizeof(int64_t);
}

size_t set_random_byte_at_random_offset(uint8_t *buffer, size_t size) {
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

VOID fuzz_registers() {
    for (REG reg : FBZergContext::argument_regs) {
        AllocatedArea *aa = preContext.find_allocated_area(reg);
        if (aa == nullptr) {
            ADDRINT value = preContext.get_value(reg);
            do {
                fuzz_strategy((uint8_t * ) & value, sizeof(value));
            } while (PIN_CheckReadAccess((void *) value) || PIN_CheckWriteAccess((void *) value));
            preContext.add(reg, value);
        } else {
            aa->fuzz();
        }
    }
    fuzzed_input = true;
}

VOID record_current_context(ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx,
                            ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11,
                            ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15,
                            ADDRINT rdi, ADDRINT rsi, ADDRINT rip, ADDRINT rbp
) {
    if (cmd_server->get_state() != ZERG_SERVER_EXECUTING) {
        wait_to_start();
    }
//    std::cout << "Recording context " << std::dec << fuzzing_run.size() << std::endl;
//    std::cout << "Func " << RTN_FindNameByAddress(rip) << ": " << INS_Disassemble(INS_FindByAddress(rip)) << std::endl;

    struct X86Context tmp = {rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15, rip, rbp};
    //std::cout << "RDI is " << (PIN_CheckReadAccess((void*)rdi) ? "" : "NOT ") << "readable. "
    //    << "RDI is " << (PIN_CheckWriteAccess((void*)rdi) ? "" : "NOT ") << "writeable." << std::endl;
    
    fuzzing_run.push_back(tmp);
    std::string curr_name = RTN_FindNameByAddress(rip);
    if (curr_name != current_function) {
        current_function = curr_name;
        executionInfo.add_function(current_function);
    }

    //tmp.prettyPrint(std::cout);
//    int64_t diff = MaxInstructions.Value() - fuzzing_run.size();
//    std::cout << std::dec << diff << std::endl;
    if (fuzzing_run.size() > max_instructions) {
//        log_message("write_to_cmd 3");
        report_failure(ZCMD_TOO_MANY_INS);
        wait_to_start();
    }
}

VOID trace_execution(TRACE trace, VOID *v) {
    if (RTN_Valid(target)) {
        for (BBL b = TRACE_BblHead(trace); BBL_Valid(b); b = BBL_Next(b)) {
            for (INS ins = BBL_InsHead(b); INS_Valid(ins); ins = INS_Next(ins)) {
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

EXCEPT_HANDLING_RESULT globalSegfaultHandler(THREADID tid, EXCEPTION_INFO *exceptionInfo, PHYSICAL_CONTEXT
*physContext, VOID *v) {
    std::stringstream ss;
    if (cmd_server) {
        cmd_server->stop();
        delete cmd_server;
    }
    ss << "Global segfault handler called: " << PIN_ExceptionToString(exceptionInfo);
    log_error(ss);
    return EHR_UNHANDLED;
}

const std::string getCurrentContext(const CONTEXT *ctx, UINT32 sig) {
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
    return ss.str();
}

VOID displayCurrentContext(const CONTEXT *ctx, UINT32 sig) {
    log_message(getCurrentContext(ctx, sig).c_str());
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
                return false;
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

void redirect_control_to_main(CONTEXT *ctx) {
    if (INS_Valid(first_ins)) {
        std::stringstream msg;
        msg << "Thread " << PIN_ThreadId() << " redirecting control to 0x" << std::hex << first_ins_addr;
        log_message(msg);
        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, first_ins_addr);
    } else {
        log_message("Could not redirect control");
    }
}

BOOL catchSegfault(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
//      std::cout << PIN_ExceptionToString(pExceptInfo) << std::endl;
//      std::cout << "Fuzzing run size: " << std::dec << fuzzing_run.size() <<
//      std::endl; displayCurrentContext(ctx); currentContext.prettyPrint();

  if (!fuzzed_input) {
//        log_message("write_to_cmd 4");
        report_failure(ZCMD_FAILED_CTX, ctx);
        redirect_control_to_main(ctx);
        return false;
    } else if (PIN_GetExceptionClass(PIN_GetExceptionCode(pExceptInfo)) != EXCEPTCLASS_ACCESS_FAULT) {
//        log_message("write_to_cmd 5");
        report_failure(ZCMD_ERROR, ctx);
        redirect_control_to_main(ctx);
        return false;
    }

    {
        ADDRINT faulting_addr = -1;
        if (!PIN_GetFaultyAccessAddress(pExceptInfo, &faulting_addr)) {
            std::stringstream msg;
            INS faulty_ins = INS_FindByAddress(fuzzing_run.back().rip);
            msg << "Could not find faulty address for instruction at 0x" << std::hex << INS_Address(faulty_ins)
                << " (" << INS_Disassemble(faulty_ins) << ")";
            log_message(msg);
            report_failure(ZCMD_ERROR, ctx);
            redirect_control_to_main(ctx);
            return false;
        }
        std::stringstream log;
        std::vector<struct TaintedObject> taintedObjs;
        REG taint_source = REG_INVALID();
        INS last_taint_ins = INS_Invalid();
        for (std::vector<struct X86Context>::reverse_iterator it = fuzzing_run.rbegin();
             it != fuzzing_run.rend(); ++it) {
            log.str(std::string());
            struct X86Context &c = *it;
            INS ins = INS_FindByAddress(c.rip);
            if (!INS_Valid(ins)) {
                log << "Could not find failing instruction at 0x" << std::hex << c.rip << std::endl;
                log_message(log);
                report_failure(ZCMD_ERROR, ctx);
                redirect_control_to_main(ctx);
                return false;
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
                for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
                    REG possible_source = INS_OperandMemoryBaseReg(ins, i);
//                    std::cout << std::dec << i << ": " << REG_StringShort(possible_source) << std::endl;
                    if (REG_valid(possible_source) &&
                        compute_effective_address(ins, fuzzing_run.back(), i) == faulting_addr) {
                        taint_source = possible_source;
                        break;
                    }
                }

                if (!REG_valid(taint_source)) {
                    std::stringstream ss;
                    ss << "Could not find valid base register for instruction: " << INS_Disassemble(ins);
                    log_message(ss);
                    redirect_control_to_main(ctx);
                    report_failure(ZCMD_ERROR, ctx);
                    return false;
                }
                add_taint(taint_source, taintedObjs);
                continue;
            }

            if (INS_IsLea(ins) || INS_Category(ins) == XED_CATEGORY_DATAXFER) {
                REG wreg = REG_INVALID();
                ADDRINT writeAddr = 0;
                if (INS_OperandIsReg(ins, 0)) {
                    wreg = INS_OperandReg(ins, 0);
//                    log << "\tWrite register is " << REG_StringShort(wreg) << std::endl;
                } else if (INS_OperandIsMemory(ins, 0)) {
//                    log << "\tOperandIsMemory" << std::endl;
                    wreg = INS_OperandMemoryBaseReg(ins, 0);
                    if (!REG_valid(wreg)) {
                        writeAddr = compute_effective_address(ins, c);
                    }
                } else {
//                    log << "Write operand is not memory or register: " << INS_Disassemble(ins) << std::endl;
//                    log_error(log);
                    continue;
                }
                log_message(log);

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
                    log << "Read operand is not a register, memory address, or immediate: " << INS_Disassemble(ins) <<
                        std::endl;
                    log << "OperandIsAddressGenerator: " << INS_OperandIsAddressGenerator(ins, 1) << std::endl;
                    log << "OperandIsFixedMemop: " << INS_OperandIsFixedMemop(ins, 1) << std::endl;
                    log << "OperandIsImplicit: " << INS_OperandIsImplicit(ins, 1) << std::endl;
                    log << "Base register: " << REG_StringShort(INS_MemoryBaseReg(ins)) << std::endl;
                    log << "Category: " << CATEGORY_StringShort(INS_Category(ins)) << std::endl;
                    for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
                        log << "Operand " << std::dec << i << " reg: " << REG_StringShort(INS_OperandReg(ins, i)) <<
                            std::endl;
                    }

                    log_message(log);
                    continue;
                }

                log_message(log);
                last_taint_ins = ins;
                faulting_addr = compute_effective_address(ins, c, 1);
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
            struct TaintedObject &taintedObject = taintedObjs.back();

            if (!create_allocated_area(taintedObject, faulting_addr)) {
//                log_message("write_to_cmd 6");
                report_failure(ZCMD_ERROR, ctx);
                redirect_control_to_main(ctx);
            }
        } else {
            log_message("Taint analysis failed for the following context: ");
            log_message(getCurrentContext(ctx, 0));
            std::stringstream msg;
            msg << "Faulting instruction (0x" << std::hex << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP)
                << "): " << INS_Disassemble(INS_FindByAddress(PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP)));
            log_message(msg);
//            log_message("write_to_cmd 7");
            report_failure(ZCMD_ERROR, ctx);
            redirect_control_to_main(ctx);
        }

//        reset_to_preexecution(ctx);
    }

//    preContext.prettyPrint();
//    currentContext.prettyPrint();
    currentContext >> ctx;
//    fuzz_registers(ctx);
//    PIN_SaveContext(ctx, &preexecution);
//    displayCurrentContext(ctx);
//    log_message("Ending segfault handler");
    return false;
}

void report_success(CONTEXT *ctx, THREADID tid) {
    currentContext << ctx;
    currentContext.set_syscalls(syscalls);
//    currentContext.prettyPrint();

//    log_message("write_to_cmd 8");
    if (fuzzed_input) {
        ZergMessage msg(ZMSG_OK);
        msg.add_contexts(preContext, currentContext);
        write_to_cmd_server(msg);
    } else {
        std::stringstream msg2;
        msg2 << "Expected context" << std::endl;
        expectedContext.prettyPrint(msg2);
        msg2 << std::endl;
        msg2 << "Current context" << std::endl;
        currentContext.prettyPrint(msg2);
        log_message(msg2);

        bool contexts_equal = (currentContext == expectedContext);
        if (!contexts_equal) {
            std::stringstream msg;
            msg << "Ending context does not match expected" << std::endl;
            msg << std::endl;

            log_message(msg);

        }
        zerg_message_t response = (contexts_equal ? ZMSG_OK : ZMSG_FAIL);
        ZergMessage msg(response);
        write_to_cmd_server(msg);
    }

    wait_to_start();
}

void report_failure(zerg_cmd_result_t reason, CONTEXT *ctx) {
    char *buf = strdup(ZergCommand::result_to_str(reason));
    size_t len = strlen(buf) + 1;
    ZergMessage msg(ZMSG_FAIL, len, buf);
    write_to_cmd_server(msg);
    free(buf);
}

void start_cmd_server(void *v) {
    cmd_server->start();
    delete cmd_server;
}

/* Add the last instruction address as a return address to allow for some optimizations */
void adjust_stack_down(CONTEXT *ctx) {
    if (!adjusted_stack) {
        log_message("Adjusting stack down");
        ADDRINT orig_rbp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP);
        ADDRINT orig_rsp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP);
        std::stringstream msg;

        log_message(msg);
        EXCEPTION_INFO exception_info;
        size_t bytes_copied = PIN_SafeCopyEx((void *) orig_rbp, &last_ins_addr, sizeof(last_ins_addr), &exception_info);
        log_message(msg);
        if (bytes_copied == 0) {
            msg << PIN_ExceptionToString(&exception_info);
            log_error(msg);
        }
        orig_rbp -= sizeof(last_ins_addr);
        orig_rsp -= sizeof(last_ins_addr);
        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RBP, orig_rbp);
        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RSP, orig_rsp);
        adjusted_stack = true;
        log_message("done");
    }
}

zerg_cmd_result_t handle_set_target(ZergMessage &zmsg) {
    std::stringstream msg;
    log_message(msg);
    PIN_LockClient();
    RTN new_target = RTN_Invalid();
    if (zmsg.type() == ZMSG_SET_TGT) {
        uintptr_t new_target_addr;
        memcpy(&new_target_addr, zmsg.data(), sizeof(new_target_addr));
        msg << "Setting new target to 0x" << std::hex << new_target_addr;
        log_message(msg);
        new_target = RTN_FindByAddress(new_target_addr);
    } else if (zmsg.type() == ZMSG_SET_SO_TGT) {
        if (!IMG_Valid(target_so)) {
            msg << "Target shared object is invalid";
            log_message(msg);
            PIN_UnlockClient();
            return ZCMD_ERROR;
        }
        msg << "Setting new target to " << (const char *) zmsg.data() << " in SO target " << IMG_Name(target_so);
        log_message(msg);
        new_target = RTN_FindByName(target_so, (const char *) zmsg.data());
    } else if (zmsg.type() == ZMSG_SET_RUST_TGT) {
        IMG img = IMG_FindImgById(imgId);
        if (IMG_Valid(img)) {
            msg << "Setting new target to " << (const char *) zmsg.data() << " in Rust binary";
            log_message(msg);
            new_target = RTN_FindByName(img, (const char *) zmsg.data());
        }
    }
    if (!RTN_Valid(new_target)) {
        msg << "Could not find valid target";
        log_message(msg);
        PIN_UnlockClient();
        return ZCMD_ERROR;
    }

    if (RTN_Valid(target)) {
        PIN_RemoveInstrumentationInRange(RTN_Address(target), RTN_Address(target) + RTN_Size(target));
    }

    msg << "Found target: " << RTN_Name(new_target) << " at 0x" << std::hex << RTN_Address(new_target) << std::endl;
    log_message(msg);
    msg << "Instrumenting returns...";
    int instrument_sites = 0;
    RTN_Open(new_target);
    INS_InsertCall(RTN_InsHead(new_target), IPOINT_BEFORE, (AFUNPTR) adjust_stack_down, IARG_CONTEXT, IARG_END);
    for (INS ins = RTN_InsHead(new_target); INS_Valid(ins); ins = INS_Next(ins)) {
        if (INS_IsRet(ins)) {
            instrument_sites++;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) report_success, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
        }
    }
    instrument_sites++;
    INS_InsertCall(RTN_InsTail(new_target), IPOINT_BEFORE, (AFUNPTR) report_success, IARG_CONTEXT,
                   IARG_THREAD_ID, IARG_END);

    last_ins_addr = INS_Address(RTN_InsTail(new_target));
    RTN_Close(new_target);
    PIN_UnlockClient();

    target = new_target;

    msg << "done. ";
    msg << "Number of instrument sites = " << std::dec << instrument_sites;
    log_message(msg);
    return ZCMD_OK;
}

zerg_cmd_result_t handle_fuzz_cmd() {
    fuzz_registers();
    return ZCMD_OK;
}

zerg_cmd_result_t handle_execute_cmd() {
    fuzzing_run.clear();
    executionInfo.reset();
    adjusted_stack = false;
    currentContext = preContext;
    currentContext >> &snapshot;
    PIN_SetContextReg(&snapshot, LEVEL_BASE::REG_RIP, RTN_Address(target));
    PIN_SetContextReg(&snapshot, LEVEL_BASE::REG_RBP, PIN_GetContextReg(&snapshot, LEVEL_BASE::REG_RSP));
    std::stringstream msg;
    msg << "About to start executing at "
        << std::hex << RTN_Address(target) << "(" << RTN_Name(target) << ")"
        << " with context " << std::endl;
    preContext.prettyPrint(msg);
    log_message(msg);

    PIN_ExecuteAt(&snapshot);
    log_message("PIN_ExecuteAt returned magically");
    return ZCMD_ERROR;
}

zerg_cmd_result_t handle_reset_cmd() {
    return ZCMD_OK;
}

zerg_cmd_result_t handle_get_exe_info_cmd() {
    ZergMessage msg(ZMSG_OK);
    if (msg.add_exe_info(executionInfo) > 0) {
        write_to_cmd_server(msg);
        return ZCMD_OK;
    } else {
        return ZCMD_ERROR;
    }
}

zerg_cmd_result_t handle_set_ctx_cmd(ZergMessage &msg) {
    std::stringstream all_ctxs(std::ios::in | std::ios::out | std::ios::binary);
    for (size_t i = 0; i < msg.size(); i++) {
        all_ctxs << ((char *) msg.data())[i];
    }

    all_ctxs >> preContext;
    all_ctxs >> expectedContext;

    fuzzed_input = false;
    ctx_count++;
    std::stringstream logmsg;
    logmsg << "Set context " << ctx_count;
    log_message(logmsg);
    return ZCMD_OK;
}

zerg_cmd_result_t handle_cmd() {
    ZergMessage *msg = nullptr;
    std::stringstream log_msg;
    msg = read_from_cmd_server();
    if (!msg) {
        log_message("Could not read command from server");
        return ZCMD_ERROR;
    }

    zerg_cmd_result_t result = ZCMD_ERROR;
    switch (msg->type()) {
        case ZMSG_SET_TGT:
        case ZMSG_SET_RUST_TGT:
            log_message("Received SetTargetCommand");
            result = handle_set_target(*msg);
            break;
        case ZMSG_SET_SO_TGT:
            log_message("Received SetSharedTargetCommand");
            result = handle_set_target(*msg);
            break;
        case ZMSG_FUZZ:
            log_message("Received FuzzCommand");
            result = handle_fuzz_cmd();
            break;
        case ZMSG_EXECUTE:
            log_message("Received ExecuteCommand");
            result = handle_execute_cmd();
            break;
        case ZMSG_RESET:
            log_message("Received ResetCommand");
            result = handle_reset_cmd();
            break;
        case ZMSG_SET_CTX:
            log_message("Received SetContextCommand");
            result = handle_set_ctx_cmd(*msg);
            break;
        case ZMSG_EXIT:
            log_message("Received ExitCommand");
            cleanup(0);
            break;
        case ZMSG_GET_EXE_INFO:
            log_message("Received SendExecuteInfoCommand");
            result = handle_get_exe_info_cmd();
            break;
        default:
            log_msg << "Unknown command: " << msg->str();
            log_message(log_msg);
            result = ZCMD_ERROR;
            break;
    }

    delete msg;
    return result;
}

void begin_execution(CONTEXT *ctx) {
    std::stringstream log_msg;
    if (!sent_initial_ready) {
        PIN_SaveContext(ctx, &snapshot);
        for (REG reg : FBZergContext::argument_regs) {
            preContext.add(reg, (ADDRINT) 0);
        }
        log_message("Starting execution with snapshot ");
        log_message(getCurrentContext(&snapshot, 0));

        ZergMessage ready(ZMSG_READY);
        write_to_cmd_server(ready);
        sent_initial_ready = true;
    }
    wait_to_start();
}

void wait_to_start() {
    std::stringstream log_msg;
    while (true) {
        log_message("Executor waiting for command");
        FD_SET(internal_pipe_in[0], &exe_fd_set_in);
        if (select(FD_SETSIZE, &exe_fd_set_in, nullptr, nullptr, nullptr) > 0) {
            if (FD_ISSET(internal_pipe_in[0], &exe_fd_set_in)) {
                zerg_cmd_result_t result = handle_cmd();
                if (result == ZCMD_OK) {
//                    log_message("cmd server 9");
                    ZergMessage msg(ZMSG_OK);
                    write_to_cmd_server(msg);
                } else {
//                    log_message("cmd server 10");
                    report_failure(result);
                }
            }
        } else {
            log_message("Select <= 0");
            cleanup(0);
        }
    }
}

VOID FindMain(IMG img, VOID *v) {
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
        return;
    }

    RTN main;
    if (!KnobRustMain.Value().empty()) {
        main = RTN_FindByName(img, KnobRustMain.Value().c_str());
    } else {
        main = RTN_FindByName(img, "main");
    }
    if (RTN_Valid(main)) {
        RTN_Open(main);
        if (is_executable_fbloader(img)) {
            const char *shared_so_cname = (const char *) v;
            std::string shared_so_name(shared_so_cname);
            target_so = IMG_Open(shared_so_name);
            if (!IMG_Valid(target_so)) {
                std::stringstream ss;
                ss << "Could not open shared object " << shared_so_name;
                log_error(ss);
            }
            first_ins = RTN_InsTail(main);
            first_ins_addr = INS_Address(first_ins);
            imgId = IMG_Id(target_so);
        } else {
            first_ins = RTN_InsHead(main);
            first_ins_addr = INS_Address(first_ins);
            imgId = IMG_Id(img);
        }

        std::stringstream msg;
        msg << "Address of first_ins = 0x" << std::hex << first_ins_addr;
        log_message(msg);

        msg << "Adding call to wait_to_start to " << RTN_Name(main) << "(0x" << std::hex << RTN_Address(main)
            << ")";
        log_message(msg);
        INS_InsertCall(first_ins, IPOINT_BEFORE, (AFUNPTR) begin_execution, IARG_CONTEXT, IARG_END);
        RTN_Close(main);
    } else {
        std::stringstream ss;
        ss << "Could not find main!" << std::endl;
        log_error(ss);
    }
}

void track_syscalls(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (cmd_server->get_state() == ZERG_SERVER_EXECUTING) {
        ADDRINT syscall_num = PIN_GetSyscallNumber(ctx, std);
        syscalls.insert(syscall_num);
    }
}

int main(int argc, char **argv) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        return usage();
    }

    srand(time(NULL));
    if (!KnobLogFile.Value().empty()) {
        log_out.open(KnobLogFile.Value().c_str(), std::ios::app);
        if (!log_out) {
            std::cerr << "Could not open log at " << KnobLogFile.Value() << std::endl;
            PIN_ExitApplication(1);
        }
    }

    std::stringstream ss;
    ss << "Starting Zergling as process " << PIN_GetPid() << "..." << std::endl;
    log_message(ss);

    if (pipe(internal_pipe_in) != 0 || pipe(internal_pipe_out) != 0) {
        log_error("Error creating internal pipe");
    }

    FD_ZERO(&exe_fd_set_in);
    FD_ZERO(&exe_fd_set_out);
    FD_SET(internal_pipe_in[0], &exe_fd_set_in);
    FD_SET(internal_pipe_out[1], &exe_fd_set_out);

    ss << "Opening command in pipe " << KnobInPipe.Value();
    log_message(ss);
    cmd_in = open(KnobInPipe.Value().c_str(), O_RDONLY);
    if (cmd_in < 0) {
        ss << "Could not open in pipe: " << strerror(errno);
        log_error(ss);
    }
    close(cmd_in);

    ss << "Opening command out pipe " << KnobOutPipe.Value();
    log_message(ss);
    cmd_out = open(KnobOutPipe.Value().c_str(), O_WRONLY);
    if (cmd_out < 0) {
        ss << "Could not open out pipe: " << strerror(errno);
        log_error(ss);
    }
    close(cmd_out);
    log_message("done opening command pipes");

    log_message("Creating command server");
    std::string cmd_log = KnobCmdLogFile.Value();

    cmd_server = new ZergCommandServer(internal_pipe_in[1], internal_pipe_out[0], KnobInPipe.Value(),
                                       KnobOutPipe.Value(), cmd_log);
    log_message("done");

    IMG_AddInstrumentFunction(FindMain, argv[argc - 1]);
    TRACE_AddInstrumentFunction(trace_execution, nullptr);
    PIN_AddSyscallEntryFunction(track_syscalls, nullptr);
    PIN_SpawnInternalThread(start_cmd_server, nullptr, 0, nullptr);

    PIN_InterceptSignal(SIGSEGV, catchSegfault, nullptr);
    PIN_AddInternalExceptionHandler(globalSegfaultHandler, nullptr);

    log_message("Starting");
    PIN_StartProgram();

    return 0;
}
