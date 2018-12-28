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
#include "FuzzResults.h"
#include "fosbin-zergling.h"

CONTEXT snapshot;
//CONTEXT preexecution;

KNOB <ADDRINT> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "target", "0", "The target address of the fuzzing target");
KNOB <uint32_t> FuzzCount(KNOB_MODE_WRITEONCE, "pintool", "fuzz-count", "4", "The number of times to fuzz a target");
KNOB <uint32_t> FuzzTime(KNOB_MODE_WRITEONCE, "pintool", "fuzz-time", "0",
                         "The number of minutes to fuzz. Ignores fuzz-count if greater than 0.");
KNOB <uint64_t> MaxInstructions(KNOB_MODE_WRITEONCE, "pintool", "ins", "1000000",
                                "The max number of instructions to run per fuzzing round");
KNOB <std::string> KnobOutName(KNOB_MODE_WRITEONCE, "pintool", "out", "fosbin-fuzz.bin",
                               "The name of the file to write "
                               "fuzz output");
RTN target;
uint32_t fuzz_count;
time_t fuzz_end_time;
TLS_KEY log_key;
FBZergContext preContext;
FBZergContext postContext;

std::ofstream infofile;
std::vector<struct X86Context> fuzzing_run;


INT32 usage() {
    std::cerr << "FOSBin Zergling -- Causing Havoc in small places" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

inline BOOL timed_fuzz() { return FuzzTime.Value() > 0; }

INS INS_FindByAddress(ADDRINT addr) {
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
    return ret;
}

VOID reset_to_context(CONTEXT *ctx) {
    fuzz_count++;

    if (!timed_fuzz()) {
        if (fuzz_count > FuzzCount.Value()) {
            std::cout << "Stopping fuzzing at " << std::dec << fuzz_count - 1 << " of " << FuzzCount.Value()
                      << std::endl;
            PIN_ExitApplication(0);
        }
    } else {
        if (time(NULL) >= fuzz_end_time) {
            std::cout << "Stopping fuzzing after " << std::dec << FuzzTime.Value() << " minute"
                      << (FuzzTime.Value() > 1 ? "s" : "") << std::endl;
            std::cout << "Total fuzzing iterations: " << std::dec << fuzz_count - 1 << std::endl;
            PIN_ExitApplication(0);
        }
    }

    postContext.reset_context(ctx, preContext);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, RTN_Address(target));
    fuzzing_run.clear();
}

VOID reset_context(CONTEXT *ctx) {
    reset_to_context(ctx);
}

VOID reset_to_preexecution(CONTEXT *ctx) {
    postContext = preContext;
    reset_to_context(ctx);
}

ADDRINT gen_random() {
    return ((((ADDRINT) rand() << 0) & 0x000000000000FFFFull) |
            (((ADDRINT) rand() << 16) & 0x00000000FFFF0000ull) |
            (((ADDRINT) rand() << 32) & 0x0000FFFF00000000ull) |
            (((ADDRINT) rand() << 48) & 0xFFFF000000000000ull)
    );
}

VOID fuzz_registers(CONTEXT *ctx) {
    for (REG reg : FBZergContext::argument_regs) {
        AllocatedArea *aa = postContext.find_allocated_area(reg);
        if (aa == nullptr) {
            PIN_SetContextReg(ctx, reg, gen_random());
        } else {
            aa->fuzz();
        }
    }
}

void output_context(const FBZergContext &ctx) {
    std::vector < AllocatedArea * > allocs;
    PinLogger &logger = *(static_cast<PinLogger *>(PIN_GetThreadData(log_key, PIN_ThreadId())));
    logger << ctx;

//    for (REG reg : FBZergContext::argument_regs) {
//        std::map<REG, AllocatedArea *>::iterator it = pointer_registers.find(reg);
//        if (it != pointer_registers.end()) {
//            allocs.push_back(it->second);
//            logger << AllocatedArea::MAGIC_VALUE;
//        } else {
//            ADDRINT val = PIN_GetContextReg(ctx, reg);
//            logger << val;
//        }
//    }
//
//    ADDRINT rax = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX);
//    logger << rax;
//
//    for (AllocatedArea *aa : allocs) {
//        logger << aa;
//    }
}

VOID start_fuzz_round(CONTEXT *ctx) {
    reset_context(ctx);
    fuzz_registers(ctx);
//    PIN_SaveContext(ctx, &preexecution);
//    std::cout << "Starting round " << std::dec << fuzz_count << std::endl;
    PIN_ExecuteAt(ctx);
}

VOID record_current_context(ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx,
                            ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11,
                            ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15,
                            ADDRINT rdi, ADDRINT rsi, ADDRINT rip, ADDRINT rbp
) {
    if (fuzzing_run.size() > MaxInstructions.Value()) {
        std::cerr << "Too many instructions! Starting Over..." << std::endl;
        start_fuzz_round(&snapshot);
    }
    struct X86Context tmp = {rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15, rip, rbp};
    fuzzing_run.push_back(tmp);
}

VOID trace_execution(TRACE trace, VOID *v) {
//    if (TRACE_Rtn(trace) == target) {
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
//    }
}

VOID end_fuzzing_round(CONTEXT *ctx, THREADID tid) {
//    std::cout << "Ending fuzzing round after executing " << std::dec << fuzzing_run.size() <<  " instructions" << std::endl;
    output_context(preContext);
    postContext << ctx;
    output_context(postContext);
    start_fuzz_round(ctx);
}

VOID begin_fuzzing(CONTEXT *ctx, THREADID tid) {
    PIN_SaveContext(ctx, &snapshot);
    start_fuzz_round(ctx);
}

VOID displayCurrentContext(const CONTEXT *ctx, UINT32 sig) {
    std::cout << "[" << (sig != SIGSEGV ? "CONTEXT" : "SIGSEGV")
              << "]=----------------------------------------------------------" << std::endl;
    std::cout << std::hex << std::internal << std::setfill('0')
              << "RAX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX) << " "
              << "RBX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX) << " "
              << "RCX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX) << std::endl
              << "RDX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX) << " "
              << "RDI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI) << " "
              << "RSI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI) << std::endl
              << "RBP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP) << " "
              << "RSP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP) << " "
              << "RIP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP) << std::endl;
    std::cout << "+-------------------------------------------------------------------" << std::endl;
}

ADDRINT compute_effective_address(INS ins, struct X86Context &ctx) {
    REG base = INS_MemoryBaseReg(ins);
    REG idx = INS_MemoryIndexReg(ins);
    UINT32 scale = INS_MemoryScale(ins);
    ADDRDELTA displacement = INS_MemoryDisplacement(ins);
//    std::cout << INS_Disassemble(ins) << std::endl;
//    std::cout << "Base: " << REG_StringShort(base)
//        << " Idx: " << REG_StringShort(idx)
//        << " Scale: 0x" << std::hex << scale
//        << " Disp: 0x" << displacement << std::endl;

//    ctx.prettyPrint(std::cout);

    ADDRINT ret = displacement + ctx.get_reg_value(base) + ctx.get_reg_value(idx) * scale;
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
//    std::cout << "\tRemoving taint from " << REG_StringShort(reg) << std::endl;
    for (std::vector<struct TaintedObject>::iterator it = taintedObjs.begin(); it != taintedObjs.end(); ++it) {
        struct TaintedObject &to = *it;
        if (to.isRegister && REG_StringShort(to.reg) == REG_StringShort(reg)) {
            taintedObjs.erase(it);
            return;
        }
    }
}

VOID add_taint(REG reg, std::vector<struct TaintedObject> &taintedObjs) {
//    std::cout << "\tAdding taint to " << REG_StringShort(reg) << std::endl;
    struct TaintedObject to;
    to.isRegister = true;
    to.reg = reg;
    taintedObjs.push_back(to);
}

VOID remove_taint(ADDRINT addr, std::vector<struct TaintedObject> &taintedObjs) {
//    std::cout << "\tRemoving taint from 0x" << std::hex << addr << std::endl;
    for (std::vector<struct TaintedObject>::iterator it = taintedObjs.begin(); it != taintedObjs.end(); ++it) {
        struct TaintedObject &to = *it;
        if (!to.isRegister && addr == to.addr) {
            taintedObjs.erase(it);
            return;
        }
    }
}

VOID add_taint(ADDRINT addr, std::vector<struct TaintedObject> &taintedObjs) {
//    std::cout << "\tAdding taint to 0x" << std::hex << addr << std::endl;
    struct TaintedObject to;
    to.isRegister = false;
    to.addr = addr;
    taintedObjs.push_back(to);
}

BOOL inline is_rbp(REG reg) {
    return LEVEL_BASE::REG_RBP == reg;
}

VOID create_allocated_area(struct TaintedObject &to, ADDRINT faulting_address) {
    if (to.isRegister) {
        AllocatedArea *aa = preContext.find_allocated_area(to.reg);
        if (aa == nullptr) {
            aa = new AllocatedArea();
            std::cout << "Creating allocated area for "
                      << REG_StringShort(to.reg) << " at 0x"
                      << std::hex << aa->getAddr() << std::endl;
            preContext.add(to.reg, aa);
        } else {
            if (!aa->fix_pointer(faulting_address)) {
                std::cerr << "Could not fix pointer in register " << REG_StringShort(to.reg) << std::endl;
                PIN_ExitApplication(1);
            }
//            std::cout << "Fixed pointer" << std::endl;
        }
    } else {
        std::cerr << "Cannot taint non-registers" << std::endl;
        PIN_ExitApplication(1);
    }
}

BOOL catchSignal(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
//    std::cout << PIN_ExceptionToString(pExceptInfo) << std::endl;
//    std::cout << "Fuzzing run size: " << std::dec << fuzzing_run.size() << std::endl;
    std::vector<struct TaintedObject> taintedObjs;
    for (std::vector<struct X86Context>::reverse_iterator it = fuzzing_run.rbegin(); it != fuzzing_run.rend(); ++it) {
        struct X86Context &c = *it;
        INS ins = INS_FindByAddress(c.rip);
        if (!INS_Valid(ins)) {
            std::cerr << "Could not find failing instruction at 0x" << std::hex << c.rip << std::endl;
            continue;
        }

//        std::cout << RTN_Name(RTN_FindByAddress(INS_Address(ins)))
//                  << "(0x" << std::hex << INS_Address(ins) << "): " << INS_Disassemble(ins) << std::endl;
//        std::cout << "\tINS_IsMemoryRead: " << (INS_IsMemoryRead(ins) ? "true" : "false") << std::endl;
//        std::cout << "\tINS_HasMemoryRead2: " << (INS_HasMemoryRead2(ins) ? "true" : "false") << std::endl;
//        std::cout << "\tINS_IsMemoryWrite: " << (INS_IsMemoryWrite(ins) ? "true" : "false") << std::endl;

        if (it == fuzzing_run.rbegin()) {
            add_taint(INS_MemoryBaseReg(ins), taintedObjs);
            continue;
        }

        if (INS_IsMemoryRead(ins) || INS_HasMemoryRead2(ins)) {
            REG base = INS_MemoryBaseReg(ins);
            REG wreg = INS_RegW(ins, 0);
            BOOL read_tainted;
            BOOL write_tainted;
            ADDRINT waddr = 0;
            ADDRINT raddr = 0;

            if (!REG_valid(base) && INS_SegPrefixIsMemoryRead(ins)) {
                /* We're reading a segment register */
                remove_taint(wreg, taintedObjs);
                continue;
            }

            if (!REG_valid(base) || !REG_valid(wreg)) {
                std::cerr << "Memory Read invalid base (" << REG_StringShort(base)
                          << ") or invalid wreg (" << REG_StringShort(wreg)
                          << ")" << std::endl;
//                PIN_ExitApplication(1);
                continue;
            }

            if (is_rbp(base)) {
                raddr = compute_effective_address(ins, c);
                read_tainted = isTainted(raddr, taintedObjs);
            } else {
                read_tainted = isTainted(base, taintedObjs);
            }

            if (is_rbp(wreg)) {
                waddr = compute_effective_address(ins, c);
                write_tainted = isTainted(waddr, taintedObjs);
            } else {
                write_tainted = isTainted(wreg, taintedObjs);
            }

            if (write_tainted && !read_tainted) {
                if (waddr) {
                    remove_taint(waddr, taintedObjs);
                } else {
                    remove_taint(wreg, taintedObjs);
                }

                if (raddr) {
                    add_taint(raddr, taintedObjs);
                } else {
                    add_taint(base, taintedObjs);
                }
            }
        } else if (INS_IsMemoryWrite(ins) && !INS_OperandIsImmediate(ins, 1)) {
            REG base = INS_MemoryBaseReg(ins);
            REG rreg = INS_RegR(ins, 1);
//            std::cout << "\tbase: " << REG_StringShort(base)
//                      << " rreg: " << REG_StringShort(rreg) << std::endl;

            BOOL read_tainted;
            BOOL write_tainted;
            ADDRINT waddr = 0;
            ADDRINT raddr = 0;
            if (!REG_valid(base) || !REG_valid(rreg)) {
                std::cerr << "Memory Write invalid base (" << REG_StringShort(base)
                          << ") or invalid rreg (" << REG_StringShort(rreg)
                          << ")" << std::endl;
//                PIN_ExitApplication(1);
                continue;
            }

            if (is_rbp(base)) {
                waddr = compute_effective_address(ins, c);
                write_tainted = isTainted(waddr, taintedObjs);
            } else {
                write_tainted = isTainted(base, taintedObjs);
            }

            if (is_rbp(rreg)) {
                raddr = compute_effective_address(ins, c);
                read_tainted = isTainted(raddr, taintedObjs);
            } else {
                read_tainted = isTainted(rreg, taintedObjs);
            }

            if (write_tainted && !read_tainted) {
                if (waddr) {
                    remove_taint(waddr, taintedObjs);
                } else {
                    remove_taint(base, taintedObjs);
                }

                if (raddr) {
                    add_taint(raddr, taintedObjs);
                } else {
                    add_taint(rreg, taintedObjs);
                }
            }
        }
    }

    if (taintedObjs.size() > 0) {
        struct TaintedObject taintedObject = taintedObjs.back();
        if (taintedObject.isRegister) {
            std::cout << "Tainted register: " << REG_StringShort(taintedObject.reg) << std::endl;
        } else {
            std::cout << "Tainted address: 0x" << std::hex << taintedObject.addr << std::endl;
        }

        /* Find the last write to the base register to find the address of the bad pointer */
        INS ins = INS_FindByAddress(fuzzing_run.back().rip);
        REG faulting_reg = INS_MemoryBaseReg(ins);
        std::cout << "Faulting reg: " << REG_StringShort(faulting_reg) << std::endl;
        ADDRINT faulting_addr = 0;
        for (std::vector<struct X86Context>::reverse_iterator it = fuzzing_run.rbegin();
             it != fuzzing_run.rend(); it++) {
            if (it == fuzzing_run.rbegin()) {
                continue;
            }
            ins = INS_FindByAddress(it->rip);
            if (INS_RegWContain(ins, faulting_reg)) {
                faulting_addr = compute_effective_address(ins, *it);
                std::cout << "Faulting addr: 0x" << std::hex << faulting_addr << std::endl;
                break;
            }
        }

        create_allocated_area(taintedObject, faulting_addr);
    } else {
        std::cerr << "Taint analysis failed for the following context: " << std::endl;
        displayCurrentContext(ctx);
    }

    fuzz_count--;
    reset_to_preexecution(ctx);
//    fuzz_registers(ctx);
//    PIN_SaveContext(ctx, &preexecution);
//    displayCurrentContext(ctx);
    return false;
}

VOID ImageLoad(IMG img, VOID *v) {
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
        return;
    }

    ADDRINT offset = IMG_LoadOffset(img);
    ADDRINT target_addr = KnobStart.Value() + offset;
    target = RTN_FindByAddress(target_addr);
    if (!RTN_Valid(target)) {
        std::cerr << "Could not find target at 0x" << std::hex << target_addr << " (0x" << offset << " + 0x" <<
                  KnobStart.Value() << ")" << std::endl;
        return;
    }
    std::cout << "Found target: " << RTN_Name(target) << " at 0x" << std::hex << RTN_Address(target) << std::endl;
    std::cout << "Instrumenting returns..." << std::flush;
    RTN_Open(target);
    for (INS ins = RTN_InsHead(target); INS_Valid(ins); ins = INS_Next(ins)) {
        if (INS_IsRet(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) end_fuzzing_round, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
        }
    }
    RTN_Close(target);
    std::cout << "done." << std::endl;

    ADDRINT main_addr = IMG_Entry(img);
    RTN main = RTN_FindByAddress(main_addr);
    if (RTN_Valid(main)) {
        RTN_Open(main);
        INS_InsertCall(RTN_InsHead(main), IPOINT_BEFORE, (AFUNPTR) begin_fuzzing, IARG_CONTEXT, IARG_THREAD_ID,
                       IARG_END);
        RTN_Close(main);
    } else {
        std::cerr << "Could not find main!" << std::endl;
        exit(1);
    }
    return;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v) {
    std::string fname = RTN_Name(target) + "." + decstr(tid) + ".ctx";
    PinLogger *logger = new PinLogger(tid, fname);
    PIN_SetThreadData(log_key, logger, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v) {
    PinLogger *logger = static_cast<PinLogger *>(PIN_GetThreadData(log_key, tid));
    delete logger;
    PIN_SetThreadData(log_key, nullptr, tid);
}

void initialize_system() {
    srand(time(NULL));
    std::string infoFileName = KnobOutName.Value() + ".info";
    infofile.open(infoFileName.c_str(), std::ios::out | std::ios::app);

    log_key = PIN_CreateThreadDataKey(0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    fuzz_end_time = time(NULL) + 60 * FuzzTime.Value();
}

int main(int argc, char **argv) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        return usage();
    }

    if (!KnobStart.Value()) {
        return usage();
    }
    initialize_system();

    if (!timed_fuzz()) {
        std::cout << "Fuzzing 0x" << std::hex << KnobStart.Value() << std::dec << " " << FuzzCount.Value() << " times."
                  << std::endl;
    } else {
        std::cout << "Fuzzing 0x" << std::hex << KnobStart.Value() << " for " << std::dec << FuzzTime.Value()
                  << " minute" << (FuzzTime.Value() > 1 ? "s" : "") << std::endl;
    }

    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    TRACE_AddInstrumentFunction(trace_execution, nullptr);
    PIN_InterceptSignal(SIGSEGV, catchSignal, nullptr);
    PIN_StartProgram();

    return 0;
}
