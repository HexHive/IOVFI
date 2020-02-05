//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_IOVEC_H
#define FOSBIN_IOVEC_H

#include "FBZergContext.h"
#include "pin.H"

#include <set>
#include <map>
#include <iostream>

struct IOVec {
    IOVec(FBZergContext &preContext, FBZergContext &postContext, std::set <ADDRINT> &systemCalls, std::map <RTN,
    std::set<ADDRINT>> executedInstructions);

    friend std::ostream &operator<<(std::ostream &out, const IOVec &ioVec);

    friend std::istream &operator>>(std::istream &in, IOVec &ioVec);

    /* Only checks post contexts */
    bool operator==(const IOVec &ioVec) const;

    bool operator!=(const IOVec &ioVec) const;

    FBZergContext preContext_;
    FBZergContext postContext_;
    std::set <ADDRINT> systemCalls_;
    float coverage_;
};


#endif //FOSBIN_IOVEC_H
