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

CONTEXT snapshot;

CONTEXT preexecution;
CONTEXT postexecution;

KNOB <ADDRINT> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "target", "0", "The target address of the fuzzing target");
KNOB <uint32_t> FuzzCount(KNOB_MODE_WRITEONCE, "pintool", "fuzz-count", "4", "The number of times to fuzz a target");
KNOB <std::string> KnobOutName(KNOB_MODE_WRITEONCE, "pintool", "out", "fosbin-fuzz.bin",
                               "The name of the file to write "
                               "fuzz output");
RTN target;
uint32_t fuzz_count;
TLS_KEY log_key;

std::ofstream infofile;

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

    friend std::ostream &operator<<(std::ostream &out, const struct X86Context &ctx);
};

std::ostream &operator<<(std::ostream &out, const struct X86Context &ctx) {
    out << ctx.rax << ctx.rbx << ctx.rcx << ctx.rdx << ctx.rsi
        << ctx.r8 << ctx.r9 << ctx.r10 << ctx.r11 << ctx.r12
        << ctx.r13 << ctx.r14 << ctx.r15 << ctx.rip;

    return out;
}

std::vector<struct X86Context> fuzzing_run;

class PinLogger {
public:
    PinLogger(THREADID tid);

    ~PinLogger();

    VOID DumpBufferToFile(struct X86Context *contexts, UINT64 numElements, THREADID tid);

private:
    std::ofstream _ofile;
};

PinLogger::PinLogger(THREADID tid) {
    std::string fname = RTN_Name(target) + "." + decstr(tid) + ".ctx";
    _ofile.open(fname.c_str(), ios::binary);
    if (!_ofile) {
        std::cerr << "Could not open logger output" << std::endl;
        exit(1);
    }
}

PinLogger::~PinLogger() {
    if (_ofile) {
        _ofile.close();
    }
}

VOID PinLogger::DumpBufferToFile(struct X86Context *contexts, UINT64 numElements, THREADID tid) {
    for (UINT64 i = 0; i < numElements; i++, contexts++) {
        _ofile << *contexts;
    }
}

VOID displayCurrentContext(CONTEXT *ctx, UINT32 sig);

INT32 usage() {
    std::cerr << "FOSBin Zergling -- Causing Havoc in small places" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

VOID reset_context(CONTEXT *ctx, THREADID tid) {
    fuzz_count++;

    if(!fuzzing_run.empty()) {
        PinLogger *logger = static_cast<PinLogger *>(PIN_GetThreadData(log_key, tid));
        for(size_t i = 0; i < fuzzing_run.size(); i++) {
            struct X86Context tmp = fuzzing_run[i];
            logger->DumpBufferToFile(&tmp, 1, tid);
        }
        fuzzing_run.clear();
    }

    if (fuzz_count > FuzzCount.Value()) {
        std::cout << "Stopping fuzzing" << std::endl;
        PIN_ExitApplication(0);
    }

    PIN_SaveContext(&snapshot, ctx);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, RTN_Address(target));
}

ADDRINT gen_random() {
    return ((((ADDRINT) rand() << 0) & 0x000000000000FFFFull) |
            (((ADDRINT) rand() << 16) & 0x00000000FFFF0000ull) |
            (((ADDRINT) rand() << 32) & 0x0000FFFF00000000ull) |
            (((ADDRINT) rand() << 48) & 0xFFFF000000000000ull)
    );
}

VOID fuzz_registers(CONTEXT *ctx) {
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDI, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RSI, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDX, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RCX, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_R8, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_R9, gen_random());
}

VOID start_fuzz_round(CONTEXT *ctx, THREADID tid) {
    reset_context(ctx, tid);
    fuzz_registers(ctx);
    PIN_SaveContext(ctx, &preexecution);
    PIN_ExecuteAt(ctx);
}

VOID record_current_context(ADDRINT rax, ADDRINT rbx, ADDRINT rcx, ADDRINT rdx,
                            ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11,
                            ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15,
                            ADDRINT rdi, ADDRINT rsi, ADDRINT rip, THREADID tid
                            ) {
    struct X86Context tmp = { rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15, rip };
    fuzzing_run.push_back(tmp);
}

VOID trace_execution(TRACE trace, VOID *v) {
    if (TRACE_Rtn(trace) == target) {
        for (BBL b = TRACE_BblHead(trace); BBL_Valid(b); b = BBL_Next(b)) {
            for (INS ins = BBL_InsHead(b); INS_Valid(ins); ins = INS_Next(ins)) {
                if (INS_IsOriginal(ins)) {
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)record_current_context,
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
                                   IARG_INST_PTR, IARG_THREAD_ID,
                                   IARG_END);
                }
            }
        }
    }
}

VOID end_fuzzing_round(CONTEXT *ctx, THREADID tid) {
    PIN_SaveContext(ctx, &postexecution);
    start_fuzz_round(ctx, tid);
}

VOID begin_fuzzing(CONTEXT *ctx, THREADID tid) {
    PIN_SaveContext(ctx, &snapshot);
    start_fuzz_round(ctx, tid);
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

BOOL catchSignal(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    reset_context(ctx, tid);
    fuzz_registers(ctx);

    PIN_SaveContext(ctx, &preexecution);
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

VOID *BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctx, VOID *buf, UINT64 numElements, VOID *v) {
    std::cout << "DUMPING BUFFER WITH " << std::dec << numElements << " ELEMENTS!" << std::endl;
    struct X86Context *contexts = (struct X86Context *) buf;
    PinLogger *logger = static_cast<PinLogger *>(PIN_GetThreadData(log_key, tid));
    logger->DumpBufferToFile(contexts, numElements, tid);
    return buf;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v) {
    PinLogger *logger = new PinLogger(tid);
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

//    insBuffer = PIN_DefineTraceBuffer(sizeof(struct X86Context), NUM_BUF_PAGES, BufferFull, 0);
//    if (insBuffer == BUFFER_ID_INVALID) {
//        outfile.close();
//        infofile.close();
//        std::cerr << "Could not allocate buffer" << std::endl;
//        exit(1);
//    }
//    std::cout << "Allocated buffer " << insBuffer << std::endl;

    log_key = PIN_CreateThreadDataKey(0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
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

    std::cout << "Fuzzing 0x" << std::hex << KnobStart.Value() << std::dec << " " << FuzzCount.Value() << " times."
              << std::endl;

    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    TRACE_AddInstrumentFunction(trace_execution, nullptr);
    PIN_InterceptSignal(SIGSEGV, catchSignal, nullptr);
    PIN_StartProgram();

    return 0;
}
