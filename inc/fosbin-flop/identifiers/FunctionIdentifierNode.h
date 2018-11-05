//
// Created by derrick on 11/5/18.
//

#ifndef FOSBIN_FUNCTIONIDENTIFIERNODE_H
#define FOSBIN_FUNCTIONIDENTIFIERNODE_H

#include "functionIdentifierNodeI.h"

namespace fbf{
        class FunctionIdentifierNode : public FunctionIdentifierNodeI {
        public:
            FunctionIdentifierNode(const char* functionName);
            virtual bool test(uintptr_t location);

            virtual void set_pass_node(std::shared_ptr<FunctionIdentifierNodeI> node) override;
            virtual void set_fail_node(std::shared_ptr<FunctionIdentifierNodeI> node) override;

        };
}

#endif //FOSBIN_FUNCTIONIDENTIFIERNODE_H
