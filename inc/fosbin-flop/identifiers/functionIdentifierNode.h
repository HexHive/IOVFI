//
// Created by derrick on 10/15/18.
//

#ifndef FOSBIN_TESTNODE_H
#define FOSBIN_TESTNODE_H

#include <fosbin-config.h>
#include <initializer_list>
#include <any>
#include <tuple>
#include "functionIdentifierNodeI.h"

namespace fbf {
    template<typename R, typename... Args>
    class FunctionIdentifierNode : public FunctionIdentifierNodeI {
    public:
        FunctionIdentifierNode(std::string &functionName, R retValue, Args... args);

        FunctionIdentifierNode(const FunctionIdentifierNode &other);

        R get_return_val();

        virtual bool test(uintptr_t location);

        virtual arg_count_t get_arg_count();

        virtual std::any get_return() const;

        const virtual std::vector<std::any> get_args() const;

    protected:
        R retVal_;
        std::tuple<Args...> args_;
        std::vector<std::any> args_v_;
    };

    template<typename R, typename... Args>
    R FunctionIdentifierNode<R, Args...>::get_return_val() { return retVal_; }

    template<typename R, typename... Args>
    std::any FunctionIdentifierNode<R, Args...>::get_return() const { return retVal_; }

    template<typename R, typename... Args>
    FunctionIdentifierNode<R, Args...>::FunctionIdentifierNode(std::string &functionName, R retVal,
                                                               Args... args):
            FunctionIdentifierNodeI(functionName), retVal_(retVal) {
        args_ = std::make_tuple(args...);
        args_v_ = {args...};
    }

    template<typename R, typename... Args>
    const std::vector<std::any> FunctionIdentifierNode<R, Args...>::get_args() const {
        return args_v_;
    }

    template<typename R, typename... Args>
    bool FunctionIdentifierNode<R, Args...>::test(uintptr_t location) {
        /* TODO: fork here and return false in case of error */
        std::function<R(Args...)> func = reinterpret_cast<R(*)(Args...)>(location);
        R retVal = std::apply(func, args_);
        long double comparison = (long double)(retVal - retVal_);
        if(comparison < 0) { comparison *= -1.0; }

        return comparison < 0.0001;
    }

    template<typename R, typename... Args>
    arg_count_t FunctionIdentifierNode<R, Args...>::get_arg_count() { return sizeof...(Args); }

    template<typename R, typename... Args>
    FunctionIdentifierNode<R, Args...>::FunctionIdentifierNode(const FunctionIdentifierNode &other) {
        args_ = other.args_;
        retVal_ = other.retVal_;
        left_ = other.left_;
        right_ = other.right_;
    }
}

#endif //FOSBIN_TESTNODE_H
