//
// Created by derrick on 2/4/20.
//

#include "IOVec.h"
#include "FBZergContext.h"

IOVec::IOVec(FBZergContext *preContext, FBZergContext *postContext,
             std::set<ADDRINT> &systemCalls,
             std::map<RTN, std::set<ADDRINT>> executedInstructions)
    : preContext_(preContext), postContext_(postContext),
      systemCalls_(systemCalls), coverage_(0.0) {
  coverage_ = computeCoverage(executedInstructions);
}

float IOVec::computeCoverage(
    std::map<RTN, std::set<ADDRINT>> executedInstructions) {
  uint64_t totalInstructionsExecuted = 0;
  uint64_t totalReachableInstructions = 0;

  float coverage = -1.0f;
  for (auto it : executedInstructions) {
    totalReachableInstructions += RTN_NumIns(it.first);
    totalInstructionsExecuted += it.second.size();
  }

  if (totalReachableInstructions > 0) {
    coverage = (float)totalInstructionsExecuted / totalReachableInstructions;
  }

  return coverage;
}

std::ostream &operator<<(std::ostream &out, const IOVec &ioVec) {
  out << *ioVec.preContext_;
  out << *ioVec.postContext_;

  out.write((char *)&ioVec.coverage_, sizeof(ioVec.coverage_));

  size_t syscall_size = ioVec.systemCalls_.size();
  out.write((const char *)&syscall_size, sizeof(syscall_size));
  for (ADDRINT i : ioVec.systemCalls_) {
    out.write((const char *)&i, sizeof(ADDRINT));
  }

  return out;
}

std::istream &operator>>(std::istream &in, IOVec &ioVec) {
  in >> *ioVec.preContext_;
  in >> *ioVec.postContext_;

  in.read((char *)&ioVec.coverage_, sizeof(ioVec.coverage_));

  size_t syscall_count = 0;
  in.read((char *)&syscall_count, sizeof(syscall_count));
  ioVec.systemCalls_.clear();
  while (syscall_count > 0) {
    ADDRINT syscall;
    in.read((char *)&syscall, sizeof(syscall));
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