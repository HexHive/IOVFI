//
// Created by derrick on 10/16/18.
//

#ifndef FOSBIN_FUNCTIONIDENTIFIERNODEI_H
#define FOSBIN_FUNCTIONIDENTIFIERNODEI_H

#include <fosbin-config.h>
#include <any>

namespace fbf {
    typedef size_t arg_count_t;

    class FunctionIdentifierNodeI {
    public:
        FunctionIdentifierNodeI(std::string &functionName);

        virtual ~FunctionIdentifierNodeI();

        virtual std::shared_ptr<FunctionIdentifierNodeI> register_passing(std::shared_ptr<fbf::FunctionIdentifierNodeI> func);

        virtual std::shared_ptr<FunctionIdentifierNodeI> register_failing(std::shared_ptr<fbf::FunctionIdentifierNodeI> func);

        virtual std::shared_ptr<FunctionIdentifierNodeI> get_passing_node();

        virtual std::shared_ptr<FunctionIdentifierNodeI> get_failing_node();

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

        virtual const std::string &get_name() const;

        virtual std::set<std::shared_ptr<fbf::FunctionIdentifierNodeI>> get_passing_funcs() const;

        virtual std::set<std::shared_ptr<fbf::FunctionIdentifierNodeI>> get_failing_funcs() const;

        virtual bool function_in_passing(std::string name) const;

        virtual bool function_in_failing(std::string name) const;

    protected:
        std::shared_ptr<FunctionIdentifierNodeI> left_, right_;
        std::string name_;
        std::set<std::shared_ptr<fbf::FunctionIdentifierNodeI>> passing_funcs_, failing_funcs_;
    };
}


#endif //FOSBIN_FUNCTIONIDENTIFIERNODEI_H
