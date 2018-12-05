//
// Created by derrick on 12/4/18.
//
#include "pin.H"
#include <iostream>
#include <iomanip>
#include <csignal>
#include <cstdlib>

CONTEXT snapshot;

KNOB<ADDRINT> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "start", "0", "The start address of the fuzzing target");
KNOB<uint32_t> FuzzCount(KNOB_MODE_WRITEONCE, "pintool", "fuzz-count", "4", "The number of times to fuzz a target");

RTN target;
uint32_t fuzz_count;

INT32 usage() {
    std::cerr << "FOSBin Zergling -- Causing Havoc in small places" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

VOID reset_context(CONTEXT* ctx) {
    fuzz_count++;
    if(fuzz_count >= FuzzCount.Value()) {
        std::cout << "Stopping fuzzing" << std::endl;
        exit(0);
    }
    PIN_SaveContext(ctx, &snapshot);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, RTN_Address(target));
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
    PIN_ExecuteAt(ctx);
}

VOID end_fuzzing_round(CONTEXT *ctx) {
    // TODO: Check if new path was traversed
    // TODO: Save post-execution state
    std::cout << "Fuzzing ended" << std::endl;
    start_fuzz_round(ctx);
}

VOID begin_fuzzing(CONTEXT *ctx) {
    PIN_SaveContext(&snapshot, ctx);
    start_fuzz_round(ctx);
}

VOID displayCurrentContext(CONTEXT *ctx, UINT32 sig)
{
    std::cout << "[" << (sig != SIGSEGV ? "CONTEXT" : "SIGSGV")
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
    std::cout << std::endl << std::endl << "/!\\ SIGSEGV received /!\\" << std::endl;
    displayCurrentContext(ctx, sig);
    std::cout << "Image Name: ";
    IMG img = IMG_FindByAddress(PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP));
    if (IMG_Valid(img)) {
        std::cout << IMG_Name(img) << std::endl;
    } else {
        std::cout << "UNKNOWN" << std::endl;
    }
    std::cout << "Function: " << RTN_FindNameByAddress(PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP)) << std::endl;

    reset_context(ctx);
    fuzz_registers(ctx);
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

    RTN main = RTN_FindByName(img, "main");
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

int main(int argc, char** argv) {
    PIN_InitSymbols();
    if(PIN_Init(argc, argv)) {
        return usage();
    }

    if(!KnobStart.Value()) {
        return usage();
    }
    srand(time(NULL));

    std::cout << "Fuzzing 0x" << std::hex << KnobStart.Value() << std::dec << " " << FuzzCount.Value() << " times."
    << std::endl;

    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_InterceptSignal(SIGSEGV, catchSignal, 0);
    PIN_StartProgram();

    return 0;
}
