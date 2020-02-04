//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_PINLOGGER_H
#define FOSBIN_PINLOGGER_H

#include "pin.H"
#include "X86Context.h"
#include "AllocatedArea.h"
#include "FBZergContext.h"

#include <fstream>
#include <string>

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

#endif //FOSBIN_PINLOGGER_H
