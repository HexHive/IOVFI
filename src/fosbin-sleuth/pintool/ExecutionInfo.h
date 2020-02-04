//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_EXECUTIONINFO_H
#define FOSBIN_EXECUTIONINFO_H

#include <iostream>
#include <string>
#include <vector>

class ExecutionInfo {
public:
    ExecutionInfo();

    ~ExecutionInfo();

    friend std::ostream &operator<<(std::ostream &out, const ExecutionInfo &info);

    void add_function(const std::string &name);

    void reset();

protected:
    std::vector <std::string> called_functions;
};

#endif //FOSBIN_EXECUTIONINFO_H
