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
    /* TODO: Add in system call output */

    return out;
}