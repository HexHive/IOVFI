//
// Created by derrick on 4/1/19.
//
#include <algorithm>

ExecutionInfo::ExecutionInfo() {}

ExecutionInfo::~ExecutionInfo() {}

std::ostream &operator<<(std::ostream &out, const ExecutionInfo &info) {
  size_t size = info.called_functions.size();
  out.write((const char *)&size, sizeof(size));
  for (size_t i = 0; i < size; i++) {
    std::string str = info.called_functions[i];
    out.write(str.c_str(), str.size() + 1);
  }
  out << std::min(1.0f, (float) executedInstructions / targetInsCount);

  return out;
}

void ExecutionInfo::reset() {
  called_functions.clear();
  executedInstructions = 0;
}

void ExecutionInfo::add_function(const std::string &name) {
  called_functions.push_back(name);
}