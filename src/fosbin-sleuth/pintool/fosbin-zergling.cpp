//
// Created by derrick on 12/4/18.
//
#include "fosbin-zergling.h"
#include "FBZergContext.h"
#include "IOVec.h"
#include "ZergCommand.h"
#include "ZergCommandServer.h"
#include "ZergMessage.h"

#include <algorithm>
#include <csetjmp>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>

#define USER_MSG_TYPE 1000

CONTEXT snapshot;

KNOB <std::string> KnobInPipe(KNOB_MODE_WRITEONCE, "pintool", "in-pipe", "",
                              "Filename of in pipe");
KNOB <std::string> KnobOutPipe(KNOB_MODE_WRITEONCE, "pintool", "out-pipe", "",
                               "Filename of out pipe");
KNOB <std::string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "log", "",
                               "/path/to/log");
KNOB <std::string> KnobCmdLogFile(KNOB_MODE_WRITEONCE, "pintool", "cmdlog", "",
                                  "/path/to/cmd/log");
KNOB <std::string> KnobRustMain(KNOB_MODE_WRITEONCE, "pintool", "rust", "",
                                "Mangled name of rust main");

RTN target = RTN_Invalid();
IMG target_so = IMG_Invalid();
IMG main_img = IMG_Invalid();
INS first_ins = INS_Invalid();
uintptr_t first_ins_addr = (uintptr_t) - 1;
uintptr_t last_ins_addr = (uintptr_t) - 1;
FBZergContext preContext;
FBZergContext currentContext;
FBZergContext expectedContext;

std::string shared_library_name;
std::set <ADDRINT> syscalls;

UINT32 imgId;
UINT32 targetImgId;

std::map <RTN, std::set<ADDRINT>> executedInstructions;

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

std::stringstream logMsg;

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

    if (log_out && log_out.is_open()) {
        log_out << message.str() << std::endl;
    } else {
        std::cout << message.str() << std::endl;
    }

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
    //  logMsg << "Writing " << msg.str() << " and " << std::dec << msg.size()
    //         << " bytes to server" << std::endl;
    //  log_message(logMsg);
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
            (((ADDRINT) rand() << 48) & 0xFFFF000000000000ull));
}

uint8_t *find_byte_at_random_offset(uint8_t *buffer, size_t buffer_size,
                                    size_t write_size) {
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
    int8_t interestingvalues[] = {0, -1, 1, CHAR_MIN, CHAR_MAX,
                                  'A', 'a', '?', ' '};

    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(int8_t));
    int8_t value =
            interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int8_t))];
    *loc = (uint8_t) value;
    return sizeof(int8_t);
}

size_t set_interesting_word_at_random_offset(uint8_t *buffer, size_t size) {
    int32_t interestingvalues[] = {0, -1, 1, INT_MIN, INT_MAX,
                                   'A', 'a', '?', ' '};
    if (size < sizeof(int32_t)) {
        return set_interesting_byte_at_random_offset(buffer, size);
    }

    int32_t *loc =
            (int32_t *) find_byte_at_random_offset(buffer, size, sizeof(int32_t));
    int32_t value =
            interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int32_t))];
    *loc = value;
    return sizeof(uint32_t);
}

size_t set_interesting_dword_at_random_offset(uint8_t *buffer, size_t size) {
    if (size < sizeof(int64_t)) {
        return set_interesting_word_at_random_offset(buffer, size);
    }

    int64_t interestingvalues[] = {0, -1, 1, LONG_MIN, LONG_MAX,
                                   'A', 'a', '?', ' '};
    int64_t value =
            interestingvalues[rand() % (sizeof(interestingvalues) / sizeof(int64_t))];
    int64_t *loc =
            (int64_t *) find_byte_at_random_offset(buffer, size, sizeof(int64_t));
    *loc = value;
    return sizeof(uint64_t);
}

size_t inc_random_byte_at_random_offset(uint8_t *buffer, size_t size) {
    uint8_t *loc = find_byte_at_random_offset(buffer, size, sizeof(int8_t));
    *loc += 1;
    return sizeof(int8_t);
}

size_t inc_random_word_at_random_offset(uint8_t *buffer, size_t size) {
    int32_t *loc =
            (int32_t *) find_byte_at_random_offset(buffer, size, sizeof(int32_t));
    *loc += 1;
    return sizeof(int32_t);
}

size_t inc_random_dword_at_random_offset(uint8_t *buffer, size_t size) {
    int64_t *loc =
            (int64_t *) find_byte_at_random_offset(buffer, size, sizeof(int64_t));
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

    uint32_t *loc =
            (uint32_t *) find_byte_at_random_offset(buffer, size, sizeof(uint32_t));
    *loc = (uint32_t) gen_random();
    return sizeof(uint32_t);
}

size_t set_random_dword_at_random_offset(uint8_t *buffer, size_t size) {
    if (size < sizeof(uint64_t)) {
        return set_random_word_at_random_offset(buffer, size);
    }

    uint64_t *loc =
            (uint64_t *) find_byte_at_random_offset(buffer, size, sizeof(uint64_t));
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
    for (size_t i = 0; i < FBZergContext::argument_count; i++) {
        REG reg = FBZergContext::argument_regs[i];
        //    logMsg << "Fuzzing register " << REG_StringShort(reg);
        AllocatedArea *aa = preContext.find_allocated_area(reg);
        if (aa == nullptr) {
            //      logMsg << " which is not an allocated area";
            //      log_message(logMsg);
            ADDRINT value = preContext.get_value(reg);
            do {
                fuzz_strategy((uint8_t * ) & value, sizeof(value));
                preContext.add(reg, value);
            } while (PIN_CheckReadAccess((void *) value) ||
                     PIN_CheckWriteAccess((void *) value));
        } else {
            //      logMsg << " which is an allocated area located at " << std::hex
            //             << (void *)aa;
            //      log_message(logMsg);
            aa->fuzz();
        }
    }
    //  log_message("Done fuzzing registers");
    fuzzed_input = true;
}

VOID record_current_context(CONTEXT *ctx) {
  if (cmd_server->get_state() != ZERG_SERVER_EXECUTING) {
    wait_to_start();
  }
  //        logMsg << "Recording context " << std::dec << fuzzing_run.size() <<
  //        std::endl;
  //  logMsg << "Func "
  //         << RTN_FindNameByAddress(PIN_GetContextReg(ctx,
  //         LEVEL_BASE::REG_RIP))
  //         << "(" << std::hex << PIN_GetContextReg(ctx, REG_INST_PTR) << "): "
  //         << INS_Disassemble(
  //                INS_FindByAddress(PIN_GetContextReg(ctx,
  //                LEVEL_BASE::REG_RIP)));
  //  log_message(logMsg);

  struct X86Context tmp = {PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_R8),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_R9),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_R10),
                           PIN_GetContextReg(ctx, LEVEL_BASE::REG_R11),
                             PIN_GetContextReg(ctx, LEVEL_BASE::REG_R12),
                             PIN_GetContextReg(ctx, LEVEL_BASE::REG_R13),
                             PIN_GetContextReg(ctx, LEVEL_BASE::REG_R14),
                             PIN_GetContextReg(ctx, LEVEL_BASE::REG_R15),
                             PIN_GetContextReg(ctx, REG_INST_PTR),
                             PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP)};

    fuzzing_run.push_back(tmp);

    ADDRINT currentAddress = PIN_GetContextReg(ctx, REG_INST_PTR);
    PIN_LockClient();
    //  IMG_TYPE type = IMG_Type(IMG_FindByAddress(currentAddress));
    //  logMsg << IMG_Name(IMG_FindByAddress(currentAddress)) << ": " << type;
    //  logMsg << IMG_TYPE::IMG_TYPE_SHAREDLIB << " " << IMG_TYPE::IMG_TYPE_
    //  log_message(logMsg);
    SEC currentSec = RTN_Sec(RTN_FindByAddress(currentAddress));
    if (SEC_Valid(currentSec) && IMG_Id(SEC_Img(currentSec)) == targetImgId && SEC_Name(currentSec) == ".text") {
//        logMsg << "Func "
//               << RTN_FindNameByAddress(PIN_GetContextReg(ctx, REG_INST_PTR))
//               << "(" << std::hex << (void *) PIN_GetContextReg(ctx, REG_INST_PTR) << " - SEC_Name = " << std::dec << SEC_Name(currentSec) << "): "
//               << INS_Disassemble(INS_FindByAddress(PIN_GetContextReg(ctx, REG_INST_PTR)));
//        log_message(logMsg);
        RTN current = RTN_FindByAddress(currentAddress);
        executedInstructions[current].insert(currentAddress);
    }
    PIN_UnlockClient();

    if (fuzzing_run.size() > max_instructions) {
        report_failure(ZCMD_TOO_MANY_INS);
        wait_to_start();
    }
}

VOID trace_execution(TRACE trace, VOID *v) {
    if (RTN_Valid(target)) {
        for (BBL b = TRACE_BblHead(trace); BBL_Valid(b); b = BBL_Next(b)) {
            for (INS ins = BBL_InsHead(b); INS_Valid(ins); ins = INS_Next(ins)) {
                //                std::cout << "Instrumenting " << INS_Disassemble(ins)
                //                << "(0x" << std::hex << INS_Address(ins) << ")"
                //                << std::endl;
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) record_current_context,
                               IARG_CONTEXT, IARG_END);
            }
        }
    }
}

EXCEPT_HANDLING_RESULT globalSegfaultHandler(THREADID tid,
                                             EXCEPTION_INFO *exceptionInfo,
                                             PHYSICAL_CONTEXT *physContext,
                                             VOID *v) {
  logMsg << "Global segfault handler called: "
         << PIN_ExceptionToString(exceptionInfo);
  log_message(logMsg);
  return EHR_UNHANDLED;
}

const std::string getCurrentContext(const CONTEXT *ctx, UINT32 sig) {
    std::stringstream ss;
    ss << "[" << (sig != SIGSEGV ? "CONTEXT" : "SIGSEGV")
       << "]=----------------------------------------------------------"
       << std::endl;
    ss << std::hex << std::internal << std::setfill('0')
       << "RAX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX)
       << " "
       << "RBX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX)
       << " "
       << "RCX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX)
       << std::endl
       << "RDX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX)
       << " "
       << "RDI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI)
       << " "
       << "RSI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI)
       << std::endl
       << "RBP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP)
       << " "
       << "RSP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP)
       << " "
       << "RIP = " << std::setw(16) << PIN_GetContextReg(ctx, REG_INST_PTR)
       << std::endl;
    ss << "+-------------------------------------------------------------------"
       << std::endl;
    return ss.str();
}

VOID displayCurrentContext(const CONTEXT *ctx, UINT32 sig) {
    log_message(getCurrentContext(ctx, sig).c_str());
}

ADDRINT compute_effective_address(REG base, REG idx, UINT32 scale,
                                  ADDRDELTA displacement,
                                  struct X86Context &ctx) {
    if (!REG_valid(base)) {
        logMsg << "Invalid base";
        log_message(logMsg);
        return 0;
    }

    ADDRINT ret =
            displacement + ctx.get_reg_value(base) + ctx.get_reg_value(idx) * scale;
    return ret;
}

ADDRINT compute_effective_address(INS ins, struct X86Context &ctx,
                                  UINT32 operand = 0) {
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
    if (ret == 0) {
        logMsg << "Invalid base instruction: " << INS_Disassemble(ins);
        log_message(logMsg);
    }
    return ret;
}

BOOL isTainted(REG reg, std::vector<struct TaintedObject> &taintedObjs) {
    for (struct TaintedObject &to : taintedObjs) {
        if (to.isRegister && REG_FullRegName(to.reg) == REG_FullRegName(reg)) {
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
//      logMsg << "\tRemoving taint from " << REG_StringShort(reg) << std::endl;
//      log_message(logMsg);
    for (std::vector<struct TaintedObject>::iterator it = taintedObjs.begin();
         it != taintedObjs.end(); ++it) {
        struct TaintedObject &to = *it;
        if (to.isRegister && REG_FullRegName(to.reg) == REG_FullRegName(reg)) {
            taintedObjs.erase(it);
            return;
        }
    }
}

VOID add_taint(REG reg, std::vector<struct TaintedObject> &taintedObjs) {
//      logMsg << "\tAdding taint to " << REG_StringShort(reg) << std::endl;
//      log_message(logMsg);
    struct TaintedObject to;
    to.isRegister = true;
    to.reg = REG_FullRegName(reg);
    taintedObjs.push_back(to);
}

VOID remove_taint(ADDRINT addr,
                  std::vector<struct TaintedObject> &taintedObjs) {
//      logMsg << "\tRemoving taint from 0x" << std::hex << addr << std::endl;
//      log_message(logMsg);
    for (std::vector<struct TaintedObject>::iterator it = taintedObjs.begin();
         it != taintedObjs.end(); ++it) {
        struct TaintedObject &to = *it;
        if (!to.isRegister && addr == to.addr) {
            taintedObjs.erase(it);
            return;
        }
    }
}

VOID add_taint(ADDRINT addr, std::vector<struct TaintedObject> &taintedObjs) {
//      logMsg << "\tAdding taint to 0x" << std::hex << addr << std::endl;
//      log_message(logMsg);
    struct TaintedObject to;
    to.isRegister = false;
    to.addr = addr;
    taintedObjs.push_back(to);
}

BOOL inline is_rbp(REG reg) { return LEVEL_BASE::REG_RBP == reg; }

BOOL create_allocated_area(struct TaintedObject &to, ADDRINT faulting_address) {
    if (to.isRegister) {
        /* Fuzzing is done with currentContext */
        AllocatedArea *aa = currentContext.find_allocated_area(to.reg);
        if (aa == nullptr) {
            aa = new AllocatedArea();
            //            logMsg << "Creating allocated area (" << std::hex <<
            //            (void*)aa << ") for "
            //                      << REG_StringShort(to.reg) << " at 0x"
            //                      << std::hex << (void*)aa->getAddr();
            //            log_message(logMsg);
            preContext.add(to.reg, aa);
            currentContext = preContext;
        } else {
            if (!aa->fix_pointer(faulting_address)) {
                logMsg << "Could not fix pointer in register "
                       << REG_StringShort(to.reg) << std::endl;
                log_message(logMsg);
                return false;
            }
            AllocatedArea *tmp = preContext.find_allocated_area(to.reg);
            aa->reset_non_ptrs(*tmp);
            //            currentContext.prettyPrint();
            *tmp = *aa;
            preContext.add(to.reg, tmp);
            //            preContext.prettyPrint();
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
        logMsg << "Cannot taint non-registers. ";
        if (SEC_Valid(s)) {
            logMsg << "Address 0x" << std::hex << to.addr << " is in section "
                   << SEC_Name(s) << "of image " << IMG_Name(img);
        } else if (IMG_Valid(img)) {
            logMsg << "Address 0x" << std::hex << to.addr
                   << " could not be found in a section but is in image "
                   << IMG_Name(img);
        } else {
            logMsg << "Address 0x" << std::hex << to.addr
                   << " could not be found in an image";
        }
        log_message(logMsg);
        return false;
    }

    //    preContext.prettyPrint();
    return true;
}

void redirect_control_to_main(CONTEXT *ctx) {
    if (INS_Valid(first_ins)) {
        //    logMsg << "Thread " << PIN_ThreadId() << " redirecting control to 0x"
        //           << std::hex << first_ins_addr;
        //    log_message(logMsg);
        PIN_SetContextReg(ctx, REG_INST_PTR, first_ins_addr);
    } else {
        log_message("Could not redirect control");
    }
}

BOOL catchSegfault(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler,
                   const EXCEPTION_INFO *pExceptInfo, VOID *v) {
//        logMsg << std::dec << tid << " " << PIN_ExceptionToString(pExceptInfo);
//        log_message(logMsg);
    //    std::cout << "Fuzzing run size: " << std::dec << fuzzing_run.size() <<
    //              std::endl;
    //    displayCurrentContext(ctx);
    //    currentContext.prettyPrint();

    if (!fuzzed_input) {
//                log_message("write_to_cmd 4");
        report_failure(ZCMD_FAILED_CTX, ctx);
        redirect_control_to_main(ctx);
        return FALSE;
    } else if (PIN_GetExceptionClass(PIN_GetExceptionCode(pExceptInfo)) !=
               EXCEPTCLASS_ACCESS_FAULT) {
//        logMsg << "write_to_cmd 5: " << PIN_ExceptionToString(pExceptInfo) << std::endl;
//        log_message(logMsg);
        report_failure(ZCMD_ERROR, ctx);
        redirect_control_to_main(ctx);
        return FALSE;
    }

    {
        ADDRINT faulting_addr = -1;
        if (!PIN_GetFaultyAccessAddress(pExceptInfo, &faulting_addr)) {
            INS faulty_ins = INS_FindByAddress(fuzzing_run.back().rip);
            logMsg << "Could not find faulty address for instruction at 0x"
                   << std::hex << INS_Address(faulty_ins) << " ("
                   << INS_Disassemble(faulty_ins) << ")";
            log_message(logMsg);
            report_failure(ZCMD_ERROR, ctx);
            redirect_control_to_main(ctx);
            return FALSE;
        }
        std::vector<struct TaintedObject> taintedObjs;
        REG taint_source = REG_INVALID();
        INS last_taint_ins = INS_Invalid();
        for (std::vector<struct X86Context>::reverse_iterator it =
                fuzzing_run.rbegin();
             it != fuzzing_run.rend(); ++it) {
            logMsg.str(std::string());
            struct X86Context &c = *it;
            INS ins = INS_FindByAddress(c.rip);
            if (!INS_Valid(ins)) {
                logMsg << "Could not find failing instruction at 0x" << std::hex
                       << c.rip << std::endl;
                log_message(logMsg);
                report_failure(ZCMD_ERROR, ctx);
                redirect_control_to_main(ctx);
                return FALSE;
            }

//                  logMsg << RTN_Name(RTN_FindByAddress(INS_Address(ins))) << "(0x"
//                         << std::hex << INS_Address(ins) << "): " <<
//                         INS_Disassemble(ins)
//                         << std::endl;
//                  logMsg << "\tINS_IsMemoryRead: "
//                         << (INS_IsMemoryRead(ins) ? "true" : "false") << std::endl;
//                  logMsg << "\tINS_HasMemoryRead2: "
//                         << (INS_HasMemoryRead2(ins) ? "true" : "false") <<
//                         std::endl;
//                  logMsg << "\tINS_IsMemoryWrite: "
//                         << (INS_IsMemoryWrite(ins) ? "true" : "false") <<
//                         std::endl;
//                  logMsg << "\tCategory: " <<
//                  CATEGORY_StringShort(INS_Category(ins))
//                         << std::endl;
//                  logMsg << "\tINS_MaxNumRRegs: " << INS_MaxNumRRegs(ins) <<
//                  std::endl; for (unsigned int i = 0; i < INS_MaxNumRRegs(ins); i++)
//                  {
//                    logMsg << "\t\t" << REG_StringShort(INS_RegR(ins, i)) <<
//                    std::endl;
//                  }
//                  logMsg << "\tINS_MaxNumWRegs: " << INS_MaxNumWRegs(ins) <<
//                  std::endl; for (unsigned int i = 0; i < INS_MaxNumWRegs(ins); i++)
//                  {
//                    logMsg << "\t\t" << REG_StringShort(INS_RegW(ins, i)) <<
//                    std::endl;
//                  }
//                  logMsg << "\tINS_MemoryBaseReg: " << REG_StringShort(INS_MemoryBaseReg(ins));
//                  log_message(logMsg);

            if (it == fuzzing_run.rbegin()) {
                for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
                    REG possible_source = INS_OperandMemoryBaseReg(ins, i);
                    if (REG_valid(possible_source) &&
                        compute_effective_address(ins, fuzzing_run.back(), i) ==
                        faulting_addr) {
                        taint_source = possible_source;
                        break;
                    }
                }

                if (!REG_valid(taint_source)) {
                    logMsg << "Could not find valid base register for instruction: "
                           << INS_Disassemble(ins);
                    log_message(logMsg);
                    redirect_control_to_main(ctx);
                    report_failure(ZCMD_ERROR, ctx);
                    return FALSE;
                }
                add_taint(taint_source, taintedObjs);
                continue;
            }

            if (INS_IsLea(ins) || INS_Category(ins) == XED_CATEGORY_DATAXFER) {
                REG wreg = REG_INVALID();
                ADDRINT writeAddr = 0;
                if (INS_OperandIsReg(ins, 0)) {
                    wreg = INS_OperandReg(ins, 0);
                    //                    logMsg << "\tWrite register is " <<
                    //                    REG_StringShort(wreg) << std::endl;
                } else if (INS_OperandIsMemory(ins, 0)) {
                    //                    logMsg << "\tOperandIsMemory" << std::endl;
                    wreg = INS_OperandMemoryBaseReg(ins, 0);
                    if (!REG_valid(wreg) || wreg == LEVEL_BASE::REG_GBP) {
                        writeAddr = compute_effective_address(ins, c);
                        //                        logMsg << "\tWrite address is 0x" <<
                        //                        writeAddr << std::endl;
                    }
                    //                    logMsg << "\tWrite register is " <<
                    //                    REG_StringShort(wreg) << std::endl;
                } else {
                    logMsg << "Write operand is not memory or register: "
                           << INS_Disassemble(ins) << std::endl;
                    log_error(logMsg);
                    continue;
                }
                //                log_message(logMsg);

                if (REG_valid(wreg) && !isTainted(wreg, taintedObjs) &&
                    wreg != LEVEL_BASE::REG_GBP) {
                    //                    logMsg << "\tWrite register is not tainted" <<
                    //                    std::endl; log_message(logMsg);
                    continue;
                } else if ((!REG_valid(wreg) || wreg == LEVEL_BASE::REG_GBP) &&
                           !isTainted(writeAddr, taintedObjs)) {
                    //                    logMsg << "\tWrite address 0x" << std::hex <<
                    //                    writeAddr << " is not tainted" << std::endl;
                    //                    log_message(logMsg);
                    continue;
                }

                REG rreg = REG_INVALID();
                ADDRINT readAddr = 0;

                if (INS_OperandIsReg(ins, 1)) {
                    rreg = INS_OperandReg(ins, 1);
                    //                    logMsg << "0\tRead register is " <<
                    //                    REG_StringShort(rreg) << std::endl;
                } else if (INS_OperandIsMemory(ins, 1)) {
                    //                    rreg = INS_OperandMemoryBaseReg(ins, 1)
                    //                    if (!REG_valid(rreg) || rreg ==
                    //                    LEVEL_BASE::REG_GBP) {
                    readAddr = compute_effective_address(ins, c, 1);
                    //                    }
                } else if (INS_OperandIsImmediate(ins, 1)) {
                    continue;
                } else if (INS_OperandIsAddressGenerator(ins, 1) ||
                           INS_MemoryOperandIsRead(ins, 1)) {
                    rreg = INS_OperandMemoryBaseReg(ins, 1);
                    //                    logMsg << "1\tRead register is " <<
                    //                    REG_StringShort(rreg) << std::endl;
                } else {
                    logMsg << "Read operand is not a register, memory address, or "
                              "immediate: "
                           << INS_Disassemble(ins) << std::endl;
                    logMsg << "OperandIsAddressGenerator: "
                           << INS_OperandIsAddressGenerator(ins, 1) << std::endl;
                    logMsg << "OperandIsFixedMemop: " << INS_OperandIsFixedMemop(ins, 1)
                           << std::endl;
                    logMsg << "OperandIsImplicit: " << INS_OperandIsImplicit(ins, 1)
                           << std::endl;
                    logMsg << "Base register: " << REG_StringShort(INS_MemoryBaseReg(ins))
                           << std::endl;
                    logMsg << "Category: " << CATEGORY_StringShort(INS_Category(ins))
                           << std::endl;
                    for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
                        logMsg << "Operand " << std::dec << i
                               << " reg: " << REG_StringShort(INS_OperandReg(ins, i))
                               << std::endl;
                    }

                    log_message(logMsg);
                    continue;
                }

                //                log_message(logMsg);
                last_taint_ins = ins;
                faulting_addr = compute_effective_address(ins, c, 1);
                if (REG_valid(wreg)) {
                    if (REG_valid(rreg)) {
                        if (wreg == LEVEL_BASE::REG_GBP) {
                            if (isTainted(writeAddr, taintedObjs) &&
                                !isTainted(rreg, taintedObjs)) {
                                remove_taint(writeAddr, taintedObjs);
                                add_taint(rreg, taintedObjs);
                            }
                        } else if (isTainted(wreg, taintedObjs) &&
                                   !isTainted(rreg, taintedObjs) &&
                                   !INS_OperandIsMemory(ins, 0)) {
                            remove_taint(wreg, taintedObjs);
                            add_taint(rreg, taintedObjs);
                        }
                    } else {
                        if (isTainted(wreg, taintedObjs) &&
                            !isTainted(readAddr, taintedObjs)) {
                            remove_taint(wreg, taintedObjs);
                            add_taint(readAddr, taintedObjs);
                        }
                    }
                } else {
                    if (REG_valid(rreg)) {
                        if (isTainted(writeAddr, taintedObjs) &&
                            !isTainted(rreg, taintedObjs)) {
                            remove_taint(wreg, taintedObjs);
                            add_taint(rreg, taintedObjs);
                        }
                    } else {
                        if (isTainted(writeAddr, taintedObjs) &&
                            !isTainted(readAddr, taintedObjs)) {
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
//                                log_message("write_to_cmd 6");
                report_failure(ZCMD_ERROR, ctx);
                redirect_control_to_main(ctx);
                return FALSE;
            }
        } else {
            log_message("Taint analysis failed for the following context: ");
            log_message(getCurrentContext(ctx, 0));
            logMsg << "Faulting instruction (0x" << std::hex
                   << PIN_GetContextReg(ctx, REG_INST_PTR) << "): "
                   << INS_Disassemble(INS_FindByAddress(
                           PIN_GetContextReg(ctx, REG_INST_PTR)));
            logMsg << "\nException: " << PIN_ExceptionToString(pExceptInfo);
            log_message(logMsg);
            log_message("write_to_cmd 7");
            report_failure(ZCMD_ERROR, ctx);
            redirect_control_to_main(ctx);
            return FALSE;
        }
    }

    //    preContext.prettyPrint();
    //    currentContext.prettyPrint();
    currentContext >> ctx;
    PIN_SetContextReg(ctx, REG_INST_PTR, RTN_Address(target));
    fuzzing_run.clear();
    //    currentContext << ctx;
//        currentContext.prettyPrint();
    //    fuzz_registers(ctx);
    //    PIN_SaveContext(ctx, &preexecution);
    //    displayCurrentContext(ctx);
//    log_message("Ending segfault handler");
    return FALSE;
}

void report_success(CONTEXT *ctx, THREADID tid) {
    currentContext << ctx;

    //    log_message("write_to_cmd 8");
    if (fuzzed_input) {
        ZergMessage msg(ZMSG_OK);
        /* The last instruction does not get executed, because we redirect control, so this accounts for that */
        executedInstructions[target].insert(last_ins_addr);

        IOVec ioVec(&preContext, &currentContext, syscalls);
        msg.add_IOVec(ioVec);
        msg.add_coverage(executedInstructions);
        write_to_cmd_server(msg);
    } else {
        bool contexts_equal = (currentContext == expectedContext);
        if (!contexts_equal) {
            logMsg << "Ending context does not match expected";
            log_message(logMsg);
        } else {
            log_message("Ending contexts match");
        }
        zerg_message_t response = (contexts_equal ? ZMSG_OK : ZMSG_FAIL);
        ZergMessage msg(response);
        if (response == ZMSG_OK) {
            /* The last instruction does not get executed, because we redirect control, so this accounts for that */
            executedInstructions[target].insert(last_ins_addr);
            msg.add_coverage(executedInstructions);
        }
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

/* Add the last instruction address as a return address to allow for some
 * optimizations */
void adjust_stack_down(CONTEXT *ctx) {
    if (!adjusted_stack) {
        //        log_message("Adjusting stack down");
        ADDRINT orig_rbp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP);
        ADDRINT orig_rsp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP);

        EXCEPTION_INFO exception_info;
        size_t bytes_copied =
                PIN_SafeCopyEx((void *) orig_rbp, &last_ins_addr, sizeof(last_ins_addr),
                               &exception_info);
        if (bytes_copied == 0) {
            logMsg << PIN_ExceptionToString(&exception_info);
            log_error(logMsg);
        }
        orig_rbp -= sizeof(last_ins_addr);
        orig_rsp -= sizeof(last_ins_addr);
        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RBP, orig_rbp);
        PIN_SetContextReg(ctx, LEVEL_BASE::REG_RSP, orig_rsp);
        adjusted_stack = true;
        //        log_message("done");
    }
    preContext >> ctx;
}

RTN RTN_FindByOffset(uintptr_t target_offset) {
    RTN result = RTN_Invalid();

    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        if (IMG_IsMainExecutable(img)) {
            for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
                if (SEC_IsExecutable(sec)) {
                    logMsg << IMG_Name(img) << "\n";
                    logMsg << "Possible routines for " << SEC_Name(sec) << ":\n";
                    for (RTN r = SEC_RtnHead(sec); RTN_Valid(r); r = RTN_Next(r)) {
                        logMsg << "\t" << RTN_Name(r) << " (" << std::hex
                               << (void *) RTN_Address(r) << ")\n";
                    }
                    /* The magic number probably has to do with an ELF header entry,
                     * but it seems to work for now */
                    ADDRINT potential_address = SEC_Address(sec) + target_offset - 0x1000;
                    logMsg << "Potential address = " << std::hex
                           << (void *) potential_address << "(";
                    RTN potential_rtn = RTN_FindByAddress(potential_address);
                    if (RTN_Valid(potential_rtn)) {
                        logMsg << RTN_Name(potential_rtn);
                    } else {
                        logMsg << "Invalid";
                    }
                    logMsg << ")";
                    log_message(logMsg);
                    if (RTN_Valid(potential_rtn) &&
                        RTN_Address(potential_rtn) == potential_address) {
                        result = potential_rtn;
                        break;
                    }
                }
            }
            break;
        }
    }

    return result;
}

zerg_cmd_result_t handle_set_target(ZergMessage &zmsg) {
    PIN_LockClient();
    RTN new_target = RTN_Invalid();
    if (zmsg.type() == ZMSG_SET_TGT) {
        uintptr_t new_target_addr;
        memcpy(&new_target_addr, zmsg.data(), sizeof(new_target_addr));
        logMsg << "Setting new target to 0x" << std::hex << new_target_addr;
        log_message(logMsg);
        new_target = RTN_FindByAddress(new_target_addr);
        if (!RTN_Valid(new_target)) {
            new_target = RTN_FindByOffset(new_target_addr);
        }
    } else if (zmsg.type() == ZMSG_SET_SO_TGT) {
        if (!IMG_Valid(target_so)) {
            logMsg << "Target shared object is invalid";
            log_message(logMsg);
            PIN_UnlockClient();
            return ZCMD_ERROR;
        }
        logMsg << "Setting new target to " << (const char *) zmsg.data()
               << " in SO target " << IMG_Name(target_so);
        log_message(logMsg);
        RTN so_func = RTN_FindByName(target_so, (const char *) zmsg.data());

        new_target = RTN_FindByAddress(RTN_Address(so_func));
    } else if (zmsg.type() == ZMSG_SET_RUST_TGT) {
        IMG img = IMG_FindImgById(imgId);
        if (IMG_Valid(img)) {
            logMsg << "Setting new target to " << (const char *) zmsg.data()
                   << " in Rust binary";
            log_message(logMsg);
            new_target = RTN_FindByName(img, (const char *) zmsg.data());
        }
    }
    if (!RTN_Valid(new_target)) {
        logMsg << "Could not find valid target";
        log_message(logMsg);
        PIN_UnlockClient();
        return ZCMD_ERROR;
    }

    if (RTN_Valid(target)) {
        PIN_RemoveInstrumentationInRange(RTN_Address(target),
                                         RTN_Address(target) + RTN_Size(target));
    }

    logMsg << "Found target: " << RTN_Name(new_target) << " at 0x" << std::hex
           << RTN_Address(new_target) << std::endl;
    log_message(logMsg);
    logMsg << "Instrumenting returns...";
    int instrument_sites = 0;
    RTN_Open(new_target);
    INS_InsertCall(RTN_InsHead(new_target), IPOINT_BEFORE,
                   (AFUNPTR) adjust_stack_down, IARG_CONTEXT, IARG_END);
    for (INS ins = RTN_InsHead(new_target); INS_Valid(ins); ins = INS_Next(ins)) {
        if (INS_IsRet(ins)) {
            instrument_sites++;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) report_success, IARG_CONTEXT,
                           IARG_THREAD_ID, IARG_END);
        }
    }
    //    instrument_sites++;
    //    INS_InsertCall(RTN_InsTail(new_target), IPOINT_BEFORE, (AFUNPTR)
    //    report_success, IARG_CONTEXT,
    //                   IARG_THREAD_ID, IARG_END);

    last_ins_addr = INS_Address(RTN_InsTail(new_target));
    RTN_Close(new_target);

    target = new_target;
    targetImgId = IMG_Id(IMG_FindByAddress(RTN_Address(target)));
    PIN_UnlockClient();

    logMsg << "done. ";
    logMsg << "Number of instrument sites = " << std::dec << instrument_sites;
    log_message(logMsg);
    return ZCMD_OK;
}

zerg_cmd_result_t handle_fuzz_cmd() {
    fuzz_registers();
    return ZCMD_OK;
}

zerg_cmd_result_t handle_execute_cmd() {
    fuzzing_run.clear();
    executedInstructions.clear();
    adjusted_stack = false;
    currentContext = preContext;
    currentContext >> &snapshot;
    PIN_SetContextReg(&snapshot, REG_INST_PTR, RTN_Address(target));
    PIN_SetContextReg(&snapshot, REG_GBP,
                      PIN_GetContextReg(&snapshot, REG_STACK_PTR));
    //  logMsg << "About to start executing at " << std::hex <<
    //  RTN_Address(target)
    //         << "(" << RTN_Name(target) << ")"
    //         << " with context " << std::endl;
    //  preContext.prettyPrint(logMsg);
    //  log_message(logMsg);

    PIN_ExecuteAt(&snapshot);
    //    log_message("PIN_ExecuteAt returned magically");
    return ZCMD_ERROR;
}

zerg_cmd_result_t handle_reset_cmd() { return ZCMD_OK; }

zerg_cmd_result_t handle_set_ctx_cmd(ZergMessage &msg) {
    std::stringstream all_ctxs(std::ios::in | std::ios::out | std::ios::binary);
    for (size_t i = 0; i < msg.size(); i++) {
        all_ctxs << ((char *) msg.data())[i];
    }

    all_ctxs >> preContext;
    all_ctxs >> expectedContext;

    fuzzed_input = false;
    ctx_count++;
    return ZCMD_OK;
}

zerg_cmd_result_t handle_cmd() {
    ZergMessage *msg = nullptr;
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
            cleanup(9);
            break;
        default:
            logMsg << "Unknown command: " << msg->str();
            log_message(logMsg);
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
        for (size_t i = 0; i < FBZergContext::argument_count; i++) {
            REG reg = FBZergContext::argument_regs[i];
            preContext.add(reg, (ADDRINT) 0);
        }
        //        log_message("Starting execution with snapshot ");
        //        log_message(getCurrentContext(&snapshot, 0));

        ZergMessage ready(ZMSG_READY);
        write_to_cmd_server(ready);
        sent_initial_ready = true;
    }
    wait_to_start();
}

void wait_to_start() {
    while (true) {
        logMsg << std::dec << PIN_ThreadId() << " Executor waiting for command";
        log_message(logMsg);
        FD_SET(internal_pipe_in[0], &exe_fd_set_in);
        if (select(FD_SETSIZE, &exe_fd_set_in, nullptr, nullptr, nullptr) > 0) {
            if (FD_ISSET(internal_pipe_in[0], &exe_fd_set_in)) {
                zerg_cmd_result_t result = handle_cmd();
                if (result == ZCMD_OK) {
                    //                    log_message("cmd server 9");
                    ZergMessage msg(ZMSG_OK);
                    write_to_cmd_server(msg);
                } else {
                    log_message("cmd server 10");
                    report_failure(result);
                }
            }
        } else {
            log_message("Select <= 0");
            cleanup(3);
        }
    }
}

VOID Find_Shared(IMG img, VOID *v) {
    if (!IMG_Valid(img) || IMG_IsMainExecutable(img)) {
        return;
    }

    const char *name = (const char *) v;
    if (name == IMG_Name(img)) {
        target_so = img;
    }
}

VOID FindMain(IMG img, VOID *v) {
    if (!IMG_Valid(img)) {
        return;
    }

    if (!IMG_IsMainExecutable(img)) {
        Find_Shared(img, v);
        return;
    }

    RTN main;
    IMG target_so;
    if (!KnobRustMain.Value().empty()) {
        main = RTN_FindByName(img, KnobRustMain.Value().c_str());
    } else {
        main = RTN_FindByName(img, "main");
    }
    if (RTN_Valid(main)) {
        RTN_Open(main);
        if (is_executable_fbloader(img)) {
            first_ins = RTN_InsTail(main);
            first_ins_addr = INS_Address(first_ins);
            imgId = IMG_Id(target_so);
        } else {
            first_ins = RTN_InsHead(main);
            first_ins_addr = INS_Address(first_ins);
            imgId = IMG_Id(img);
        }

        INS_InsertCall(first_ins, IPOINT_BEFORE, (AFUNPTR) begin_execution,
                       IARG_CONTEXT, IARG_END);
        RTN_Close(main);
    } else {
        logMsg << "Could not find main!" << std::endl;
        log_error(logMsg);
    }
}

void track_syscalls(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (cmd_server->get_state() == ZERG_SERVER_EXECUTING) {
        ADDRINT syscall_num = PIN_GetSyscallNumber(ctx, std);
        syscalls.insert(syscall_num);
    }
}

void fini(INT32 code, void *v) {
    logMsg << "Exiting with code " << code;
    log_message(logMsg);
}

void ctxChange(THREADID threadId, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, void *v) {
    logMsg << std::dec << threadId << " ctxChange: ";
    switch (reason) {
        case CONTEXT_CHANGE_REASON_FATALSIGNAL:
            logMsg << "FATAL: " << std::dec << info;
            break;
        case CONTEXT_CHANGE_REASON_SIGNAL:
            logMsg << "SIGNAL: " << std::dec << info;
            break;
        case CONTEXT_CHANGE_REASON_SIGRETURN:
            logMsg << "SIGRETURN";
            break;
        default:
            logMsg << "OTHER";
            break;
    }
    log_message(logMsg);
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

    logMsg << "Starting Zergling as process " << PIN_GetPid() << "..."
           << std::endl;
    log_message(logMsg);

    if (pipe(internal_pipe_in) != 0 || pipe(internal_pipe_out) != 0) {
        log_error("Error creating internal pipe");
    }

    FD_ZERO(&exe_fd_set_in);
    FD_ZERO(&exe_fd_set_out);
    FD_SET(internal_pipe_in[0], &exe_fd_set_in);
    FD_SET(internal_pipe_out[1], &exe_fd_set_out);

    logMsg << "Opening command in pipe " << KnobInPipe.Value();
    log_message(logMsg);
    cmd_in = open(KnobInPipe.Value().c_str(), O_RDONLY);
    if (cmd_in < 0) {
        logMsg << "Could not open in pipe: " << strerror(errno);
        log_error(logMsg);
    }
    close(cmd_in);

    logMsg << "Opening command out pipe " << KnobOutPipe.Value();
    log_message(logMsg);
    cmd_out = open(KnobOutPipe.Value().c_str(), O_WRONLY);
    if (cmd_out < 0) {
        logMsg << "Could not open out pipe: " << strerror(errno);
        log_error(logMsg);
    }
    close(cmd_out);
    log_message("done opening command pipes");

    log_message("Creating command server");
    std::string cmd_log = KnobCmdLogFile.Value();

    cmd_server =
            new ZergCommandServer(internal_pipe_in[1], internal_pipe_out[0],
                                  KnobInPipe.Value(), KnobOutPipe.Value(), cmd_log);
    log_message("done");

    IMG_AddInstrumentFunction(FindMain, argv[argc - 1]);
    //    IMG_AddInstrumentFunction(Find_Shared, argv[argc - 1]);
    TRACE_AddInstrumentFunction(trace_execution, nullptr);
    PIN_AddSyscallEntryFunction(track_syscalls, nullptr);
    PIN_SpawnInternalThread(start_cmd_server, nullptr, 0, nullptr);

    PIN_InterceptSignal(SIGSEGV, catchSegfault, nullptr);
    PIN_AddInternalExceptionHandler(globalSegfaultHandler, nullptr);
    //    PIN_AddFiniFunction(fini, nullptr);
    //    PIN_AddContextChangeFunction(ctxChange, nullptr);

    log_message("Starting");
    PIN_StartProgram();

    return 0;
}
