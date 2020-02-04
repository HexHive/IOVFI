//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_IOVEC_H
#define FOSBIN_IOVEC_H

#include "FBZergContext.h"
#include "pin.H"

#include <set>
#include <iostream>

class IOVec {
public:
    IOVec(FBZergContext &preContext, FBZergContext &postContext, std::set <ADDRINT> &systemCalls, float
    coverage);

    friend std::ostream &operator<<(std::ostream &out, const IOVec &ioVec);

protected:
    FBZergContext &preContext_;
    FBZergContext &postContext_;
    std::set <ADDRINT> systemCalls_;
    float coverage_;
};


#endif //FOSBIN_IOVEC_H
