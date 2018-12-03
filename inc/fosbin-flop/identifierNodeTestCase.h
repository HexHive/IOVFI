//
// Created by derrick on 10/16/18.
//

#ifndef FOSBIN_IDENTIFIERNODETESTCASE_H
#define FOSBIN_IDENTIFIERNODETESTCASE_H

#include <identifiers/functionIdentifierInteriorNode.h>
#include <iTestCase.h>
#include <fosbin-flop/identifiers/functionIdentifierNodeI.h>

namespace fbf {
    class IdentifierNodeTestCase : public ITestCase {
    public:
        IdentifierNodeTestCase(std::shared_ptr<fbf::FunctionIdentifierNodeI> root, uintptr_t location, uint32_t arity);

        virtual const std::string get_test_name();

        virtual int run_test();

        virtual void output_result(std::ostream &out);

    protected:
        std::shared_ptr<fbf::FunctionIdentifierNodeI> root_, leaf_;
        uint32_t arity_;
    };
}

#endif //FOSBIN_IDENTIFIERNODETESTCASE_H
