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

KNOB<ADDRINT> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "start", "0", "The start address of the fuzzing target");
KNOB<uint32_t> FuzzCount(KNOB_MODE_WRITEONCE, "pintool", "fuzz-count", "4", "The number of times to fuzz a target");
KNOB<std::string> KnobOutName(KNOB_MODE_WRITEONCE, "pintool", "out", "fosbin-fuzz.bin", "The name of the file to write "
                                                                                     "fuzz output");
RTN target;
uint32_t fuzz_count;
BUFFER_ID insBuffer;

std::ofstream outfile, infofile;

VOID displayCurrentContext(CONTEXT *ctx, UINT32 sig);

INT32 usage() {
    std::cerr << "FOSBin Zergling -- Causing Havoc in small places" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

VOID reset_context(CONTEXT* ctx) {
    fuzz_count++;
    if(fuzz_count > FuzzCount.Value()) {
        std::cout << "Stopping fuzzing" << std::endl;
        exit(0);
    }
    bblsVisited.clear();

    PIN_SaveContext(&snapshot, ctx);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, RTN_Address(target));
    displayCurrentContext(ctx, 0);
}

ADDRINT gen_random() {
    return (  (((ADDRINT) rand() <<  0) & 0x000000000000FFFFull) |
              (((ADDRINT) rand() << 16) & 0x00000000FFFF0000ull) |
              (((ADDRINT) rand() << 32) & 0x0000FFFF00000000ull) |
              (((ADDRINT) rand() << 48) & 0xFFFF000000000000ull)
        );
}

VOID fuzz_registers(CONTEXT* ctx) {
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDI, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RSI, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDX, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RCX, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_R8, gen_random());
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_R9, gen_random());
}

VOID start_fuzz_round(CONTEXT* ctx) {
    reset_context(ctx);
    fuzz_registers(ctx);
    PIN_SaveContext(ctx, &preexecution);
    PIN_ExecuteAt(ctx);
}

VOID record_context(CONTEXT* ctx, struct X86FuzzingContext *dest) {
    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_RDI, (UINT8*)&dest->regs[0].value);
    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_RSI, (UINT8*)&dest->regs[1].value);
    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_RDX, (UINT8*)&dest->regs[2].value);
    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_RCX,(UINT8*) &dest->regs[3].value);
    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_R8, (UINT8*)&dest->regs[4].value);
    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_R9, (UINT8*)&dest->regs[5].value);
    PIN_GetContextRegval(ctx, LEVEL_BASE::REG_RAX, (UINT8*)&dest->ret.value);
}

VOID record_fuzz_round() {
    struct FuzzingResult result;
    result.target_addr = KnobStart.Value();
    record_context(&preexecution, &result.preexecution);
    record_context(&postexecution, &result.postexecution);

    infofile << "0x" << std::hex << KnobStart.Value()
        << "(" << RTN_Name(target) << ") finished fuzzing round" << std::endl;

    outfile.write((const char*)&result, sizeof(struct FuzzingResult));
}

VOID register_basic_block(ADDRINT bbl, UINT64 size) {
    std::cout << std::hex << bbl << std::dec << " " << size << std::endl;
    bblsVisited.push_back({bbl, size});
}

VOID trace_execution(TRACE trace, VOID *v) {
    for(BBL b = TRACE_BblHead(trace); BBL_Valid(b); b = BBL_Next(b)) {
        for(INS ins = BBL_InsHead(b); INS_Valid(ins); ins = INS_Next(ins)) {
            INS_InsertFillBuffer(ins, IPOINT_BEFORE, insBuffer, IARG_CONST_CONTEXT)
        }
    }
}

VOID end_fuzzing_round(CONTEXT *ctx) {
    std::cout << "Fuzzing ended" << std::endl;
    PIN_SaveContext(ctx, &postexecution);
    record_fuzz_round();
    start_fuzz_round(ctx);
}

VOID begin_fuzzing(CONTEXT *ctx) {
    TRACE_AddInstrumentFunction(trace_execution, nullptr);
    PIN_SaveContext(ctx, &snapshot);
    start_fuzz_round(ctx);
}

VOID displayCurrentContext(CONTEXT *ctx, UINT32 sig)
{
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

BOOL catchSignal(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
    displayCurrentContext(ctx, sig);
    std::cout << "Image Name: ";
    IMG img = IMG_FindByAddress(PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP));
    if (IMG_Valid(img)) {
        std::cout << IMG_Name(img) << std::endl;
    } else {
        std::cout << "UNKNOWN" << std::endl;
    }
    std::cout << "Function: " << RTN_FindNameByAddress(PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP)) << std::endl;

    infofile << "0x" << std::hex << KnobStart.Value()
             << "(" << RTN_Name(target) << ") issued SIGSEGV" << std::endl;

    reset_context(ctx);
    fuzz_registers(ctx);

    PIN_SaveContext(ctx, &preexecution);
    return false;
}

VOID ImageLoad(IMG img, VOID *v)
{
    if(!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
        return;
    }

    ADDRINT offset = IMG_LoadOffset(img);
    ADDRINT target_addr = KnobStart.Value() + offset;
    target = RTN_FindByAddress(target_addr);
    if(!RTN_Valid(target)) {
        std::cerr << "Could not find target at 0x" << std::hex << target_addr << " (0x" << offset << " + 0x" <<
        KnobStart.Value() << ")" << std::endl;
        return;
    }
    std::cout << "Found target: " << RTN_Name(target) << " at 0x" << std::hex << target_addr << std::endl;
    std::cout << "Instrumenting returns..." << std::flush;
    RTN_Open(target);
    for(INS ins = RTN_InsHead(target); INS_Valid(ins); ins = INS_Next(ins)) {
        if(INS_IsRet(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)end_fuzzing_round, IARG_CONTEXT, IARG_END);
        }
    }
    RTN_Close(target);
    std::cout << "done." << std::endl;

    ADDRINT main_addr = IMG_Entry(img);
    RTN main = RTN_FindByAddress(main_addr);
    if(RTN_Valid(main)) {
        RTN_Open(main);
        INS_InsertCall(RTN_InsHead(main), IPOINT_BEFORE, (AFUNPTR)begin_fuzzing, IARG_CONTEXT, IARG_END);
        RTN_Close(main);
    } else {
        std::cerr << "Could not find main!" << std::endl;
        exit(1);
    }
    return;
}

VOID* buffer_write(BUFFER_ID id, THREADID tid, const CONTEXT *ctx, VOID *buf, UINT64 numElements, VOID *v) {
    std::cout << "buffer_write called" << std::endl;
    return buf;
}

void initialize_system() {
    srand(time(NULL));
    std::string infoFileName = KnobOutName.Value() + ".info";
    outfile.open(KnobOutName.Value().c_str(), std::ios::out | std::ios::binary);
    infofile.open(infoFileName.c_str(), std::ios::out | std::ios::app);

    insBuffer = PIN_DefineTraceBuffer(sizeof(CONTEXT), BUF_PAGE_SZ, buffer_write, nullptr);
    if(insBuffer == BUFFER_ID_INVALID) {
        outfile.close();
        infofile.close();
        std::cerr << "Could not allocate buffer" << std::endl;
    }
}

int main(int argc, char** argv) {
    PIN_InitSymbols();
    if(PIN_Init(argc, argv)) {
        return usage();
    }

    if(!KnobStart.Value()) {
        return usage();
    }
    initialize_system();

    std::cout << "Fuzzing 0x" << std::hex << KnobStart.Value() << std::dec << " " << FuzzCount.Value() << " times."
    << std::endl;

    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    PIN_InterceptSignal(SIGSEGV, catchSignal, nullptr);
    PIN_StartProgram();

    return 0;
}
