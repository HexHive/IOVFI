//
// Created by derrick on 10/16/18.
//

#ifndef FOSBIN_IDENTIFIERNODETESTCASE_H
#define FOSBIN_IDENTIFIERNODETESTCASE_H

#include <fosbin-flop/identifiers/functionIdentifierNode.h>
#include "iTestCase.h"

namespace fbf {
    class IdentifierNodeTestCase : public ITestCase {
    public:
        IdentifierNodeTestCase(std::shared_ptr<fbf::FunctionIdentifierNodeI> root, uintptr_t location);

        virtual const std::string get_test_name();

        virtual int run_test();

        virtual uint64_t get_value();

        virtual uintptr_t get_location();

    protected:
        std::shared_ptr<fbf::FunctionIdentifierNodeI> root_;
        uintptr_t location_;
        std::string ided_function_;
    };
}

#endif //FOSBIN_IDENTIFIERNODETESTCASE_H
