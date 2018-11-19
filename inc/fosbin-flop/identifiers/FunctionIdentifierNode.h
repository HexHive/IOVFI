//
// Created by derrick on 11/5/18.
//

#ifndef FOSBIN_FUNCTIONIDENTIFIERNODE_H
#define FOSBIN_FUNCTIONIDENTIFIERNODE_H

#include <identifiers/functionIdentifierNodeI.h>

namespace fbf{
        class FunctionIdentifierNode : public FunctionIdentifierNodeI {
        public:
            FunctionIdentifierNode(const char* functionName, std::shared_ptr<FunctionIdentifierNodeI> confirmation);
            virtual bool test(uintptr_t location) override;
            virtual bool test_arity(uintptr_t location, arg_count_t arity) override;
            virtual arg_count_t get_arg_count() override;

            virtual void set_pass_node(std::shared_ptr<FunctionIdentifierNodeI> node) override;
            virtual void set_fail_node(std::shared_ptr<FunctionIdentifierNodeI> node) override;
        protected:
            std::shared_ptr<FunctionIdentifierNodeI> confirmation_;
        };
}

#endif //FOSBIN_FUNCTIONIDENTIFIERNODE_H
