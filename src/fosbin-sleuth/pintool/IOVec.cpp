//
// Created by derrick on 2/4/20.
//

#include "IOVec.h"
#include "FBZergContext.h"

IOVec::IOVec(FBZergContext &preContext, FBZergContext &postContext, std::set <ADDRINT> &systemCalls, float
coverage) : preContext_(preContext), postContext_(postContext), systemCalls_(systemCalls), coverage_(coverage) {}

std::ostream &operator<<(std::ostream &out, const IOVec &ioVec) {
    out << ioVec.preContext_;
    out << ioVec.postContext_;
    out << ioVec.coverage_;
    size_t syscall_size = ioVec.systemCalls_.size();
    out.write((const char *) &syscall_size, sizeof(syscall_size));
    for (ADDRINT i : ioVec.systemCalls_) {
        out.write((const char *) &i, sizeof(ADDRINT));
    }

    return out;
}