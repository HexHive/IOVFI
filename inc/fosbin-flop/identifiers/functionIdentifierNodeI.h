//
// Created by derrick on 10/16/18.
//

#ifndef FOSBIN_FUNCTIONIDENTIFIERNODEI_H
#define FOSBIN_FUNCTIONIDENTIFIERNODEI_H

#include "fosbin-flop.h"
#include <any>

namespace fbf{
        typedef size_t arg_count_t;

        class FunctionIdentifierNodeI {
            public:
            FunctionIdentifierNodeI(std::string &functionName);

            virtual ~FunctionIdentifierNodeI();

            virtual std::shared_ptr<FunctionIdentifierNodeI> get_pass_node();

            virtual std::shared_ptr<FunctionIdentifierNodeI> get_fail_node();

            virtual void set_pass_node(std::shared_ptr<FunctionIdentifierNodeI> node);

            virtual void set_fail_node(std::shared_ptr<FunctionIdentifierNodeI> node);

            virtual bool test(uintptr_t location) = 0;

            virtual arg_count_t get_arg_count() = 0;

            virtual bool is_same_return(const FunctionIdentifierNodeI &node) const = 0;

            virtual std::any get_return() const = 0;

            virtual bool args_changed() = 0;

            const virtual std::vector<std::any> get_args() const = 0;

            static bool compare_any(const std::any v1, const std::any v2);

            virtual bool operator==(const FunctionIdentifierNodeI &node) const = 0;

            virtual bool operator!=(const FunctionIdentifierNodeI &node) const;

            virtual const std::string& get_name() const;


            protected:
            std::shared_ptr<FunctionIdentifierNodeI> left_, right_;
            std::string name_;
        };
}


#endif //FOSBIN_FUNCTIONIDENTIFIERNODEI_H
