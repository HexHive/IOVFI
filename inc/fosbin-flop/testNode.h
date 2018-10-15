//
// Created by derrick on 10/15/18.
//

#ifndef FOSBIN_TESTNODE_H
#define FOSBIN_TESTNODE_H

#include <fosbin-config.h>
#include <vector>
#include <any>

namespace fbf {
    class TestNode {
    public:
        TestNode(std::vector<std::any> args, std::any returnValue);

        bool test(uintptr_t location);

        std::vector<std::any>& getArgs();
        std::any& getReturnValue();

        const static uint8_t MAX_ARGS;

    protected:
        std::vector<std::any> args_;
        std::any retVal_;
    };
}


#endif //FOSBIN_TESTNODE_H
