//
// Created by derrick on 2/4/20.
//

#include "IOVec.h"
#include "FBZergContext.h"
#include "fosbin-zergling.h"

Coverage::Coverage(std::map <RTN, std::set<ADDRINT>> &executedInstructions) : coverages() {
    PIN_LockClient();
    for (auto it : executedInstructions) {
        uintptr_t addr = RTN_Address(it.first);
        size_t totalInstructions = RTN_NumIns(it.first);
        coverages[addr] = std::make_pair(it.second, totalInstructions);
    }
    PIN_UnlockClient();
}

std::ostream &operator<<(std::ostream &out, Coverage &coverage) {
    size_t size = coverage.coverages.size();
    out.write((char *) &size, sizeof(size));
    for (const auto it : coverage.coverages) {
        std::set <ADDRINT> &instructions = coverage.coverages[it.first].first;
        size_t totalInstructions = coverage.coverages[it.first].second;
        size_t numInstructions = instructions.size();
        out.write((char *) &numInstructions, sizeof(numInstructions));
        out.write((char *) &totalInstructions, sizeof(totalInstructions));
        for (auto addr : instructions) {
            out.write((char *) &addr, sizeof(addr));
        }
    }

    return out;
}

IOVec::IOVec(FBZergContext *preContext, FBZergContext *postContext,
             std::set <ADDRINT> &systemCalls)
        : preContext_(preContext), postContext_(postContext),
          systemCalls_(systemCalls) {
}

std::ostream &operator<<(std::ostream &out, const IOVec &ioVec) {
    out << *ioVec.preContext_;
    out << *ioVec.postContext_;

    size_t syscall_size = ioVec.systemCalls_.size();
    out.write((const char *) &syscall_size, sizeof(syscall_size));
    for (ADDRINT i : ioVec.systemCalls_) {
        out.write((const char *) &i, sizeof(ADDRINT));
    }

    return out;
}

std::istream &operator>>(std::istream &in, IOVec &ioVec) {
    in >> *ioVec.preContext_;
    in >> *ioVec.postContext_;

    size_t syscall_count = 0;
    in.read((char *) &syscall_count, sizeof(syscall_count));
    ioVec.systemCalls_.clear();
    while (syscall_count > 0) {
        ADDRINT syscall;
        in.read((char *) &syscall, sizeof(syscall));
        ioVec.systemCalls_.insert(syscall);
        syscall_count--;
    }

    return in;
}

bool IOVec::operator==(const IOVec &ioVec) const {
    if (*this->postContext_ != *ioVec.postContext_) {
        return false;
    }

    if (systemCalls_.size() != ioVec.systemCalls_.size()) {
        return false;
    }

    for (ADDRINT i : systemCalls_) {
        if (ioVec.systemCalls_.find(i) == ioVec.systemCalls_.end()) {
            return false;
        }
    }

    return true;
}

bool IOVec::operator!=(const IOVec &ioVec) const { return !(*this == ioVec); }