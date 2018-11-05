//
// Created by derrick on 10/15/18.
//

#ifndef FOSBIN_TESTNODE_H
#define FOSBIN_TESTNODE_H

#include <fosbin-config.h>
#include <initializer_list>
#include <any>
#include <tuple>
#include <sys/wait.h>
#include "functionIdentifierNodeI.h"

namespace fbf {
    template<typename R, typename... Args>
    class FunctionIdentifierInternalNode : public FunctionIdentifierNodeI {
    public:
        FunctionIdentifierInternalNode(R retValue, Args... args);

        FunctionIdentifierInternalNode(const FunctionIdentifierInternalNode &other);

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
    R FunctionIdentifierInternalNode<R, Args...>::get_return_val() { return retVal_; }

    template<typename R, typename... Args>
    std::any FunctionIdentifierInternalNode<R, Args...>::get_return() const { return retVal_; }

    template<typename R, typename... Args>
    FunctionIdentifierInternalNode<R, Args...>::FunctionIdentifierInternalNode(R retVal,
                                                               Args... args):
            FunctionIdentifierNodeI(""), retVal_(retVal) {
        args_ = std::make_tuple(args...);
        args_v_ = {args...};
    }

    template<typename R, typename... Args>
    const std::vector<std::any> FunctionIdentifierInternalNode<R, Args...>::get_args() const {
        return args_v_;
    }

    template<typename R, typename... Args>
    bool FunctionIdentifierInternalNode<R, Args...>::test(uintptr_t location) {
        pid_t pid = fork();
        if(pid == 0) {
            std::function<R(Args...)> func = reinterpret_cast<R(*)(
                    Args...)>(location);
            R retVal = std::apply(func, args_);
            if constexpr (std::is_pointer_v<R>) {
                exit(std::strcmp(retVal, retVal_) == 0);
            } else {
                exit(retVal == retVal_);
            }
        } else {
            int status = 0;
            waitpid(pid, &status, 0);
            return (WIFEXITED(status) && WEXITSTATUS(status) == 1);
        }
    }

    template<typename R, typename... Args>
    arg_count_t FunctionIdentifierInternalNode<R, Args...>::get_arg_count() { return sizeof...(Args); }

    template<typename R, typename... Args>
    FunctionIdentifierInternalNode<R, Args...>::FunctionIdentifierInternalNode(const FunctionIdentifierInternalNode &other) {
        args_ = other.args_;
        retVal_ = other.retVal_;
        left_ = other.left_;
        right_ = other.right_;
    }
}

#endif //FOSBIN_TESTNODE_H
