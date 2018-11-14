//
// Created by derrick on 10/15/18.
//

#ifndef FOSBIN_TESTNODE_H
#define FOSBIN_TESTNODE_H

#include <fosbin-config.h>
#include <initializer_list>
#include <vector>
#include <tuple>
#include <sys/wait.h>
#include "functionIdentifierNodeI.h"

namespace fbf {
    template<size_t index, typename... Args>
    struct arg_checker {
        static constexpr bool check_args(std::vector<size_t> &sizes, const std::tuple<Args...> &preargs,
                                         const std::tuple<Args...> &postargs) {
            if constexpr (index < sizeof...(Args)) {
                bool expected = false;
                if constexpr(std::is_pointer_v<decltype(std::get<index>(preargs))>) {
                    expected = std::memcmp(std::get<index>(preargs), std::get<index>(postargs), sizes[index]) == 0;
                } else {
                    expected = true;
                }

                return expected && arg_checker<index + 1, Args...>::check_args(sizes, preargs, postargs);
            } else {
                return true;
            }
        }
    };


    template<typename R, typename... Args>
    class FunctionIdentifierInternalNode : public FunctionIdentifierNodeI {
    public:
        FunctionIdentifierInternalNode(R retValue,
                                       size_t retSize,
                                       std::vector<size_t> arg_sizes,
                                       std::tuple<Args...> preargs,
                                       std::tuple<Args...> postargs
        );

        FunctionIdentifierInternalNode(const FunctionIdentifierInternalNode &other);

        virtual bool test(uintptr_t location) override;

        virtual bool test_arity(uintptr_t location, arg_count_t arity) override;

        virtual arg_count_t get_arg_count() override;

    protected:
        R retVal_;
        size_t retSize_;
        std::tuple<Args...> preargs_;
        std::tuple<Args...> postargs_;
        std::vector<size_t> arg_sizes_;
    };

    template<typename R, typename... Args>
    FunctionIdentifierInternalNode<R, Args...>::FunctionIdentifierInternalNode(R retVal,
                                                                               size_t retSize,
                                                                               std::vector<size_t> arg_sizes,
                                                                               std::tuple<Args...> preargs,
                                                                               std::tuple<Args...> postargs):
            FunctionIdentifierNodeI(""), retVal_(retVal), retSize_(retSize),
            arg_sizes_(arg_sizes), preargs_(preargs), postargs_(postargs) {
    }

    template<typename R, typename... Args>
    FunctionIdentifierInternalNode<R, Args...>::FunctionIdentifierInternalNode(const
                                                                               FunctionIdentifierInternalNode<R, Args...>
                                                                               &other): FunctionIdentifierNodeI("") {
        retVal_ = other.retVal_;
        retSize_ = other.retSize_;
        preargs_ = other.preargs_;
        postargs_ = other.postargs_;
        arg_sizes_ = other.arg_sizes_;
    }

    template<typename R, typename... Args>
    bool FunctionIdentifierInternalNode<R, Args...>::test(uintptr_t location) {
        pid_t pid = fork();
        if (pid == 0) {
            bool is_equiv = true;
            std::function<R(Args...)> func = reinterpret_cast<R(*)(
                    Args...)>(location);
            R retVal = std::apply(func, preargs_);
            if constexpr (std::is_pointer_v<R>) {
                is_equiv = (std::memcmp(retVal, retVal_, retSize_) == 0);
            } else {
                is_equiv = (retVal == retVal_);
            }

            if constexpr(sizeof...(Args) > 0) {
                is_equiv &= arg_checker<0, Args...>::check_args(arg_sizes_, preargs_, postargs_);
            }

            exit(is_equiv == true);
        } else {
            int status = 0;
            waitpid(pid, &status, 0);
            return (WIFEXITED(status) && WEXITSTATUS(status) == 1);
        }
    }

    template<typename R, typename... Args>
    arg_count_t FunctionIdentifierInternalNode<R, Args...>::get_arg_count() { return sizeof...(Args); }

    template<typename R, typename... Args>
    bool FunctionIdentifierInternalNode<R, Args...>::test_arity(uintptr_t location, arg_count_t arity) {
        if (arity != get_arg_count()) {
            LOG_DEBUG << std::hex << location << std::dec << " has arity " << arity << " and does not match " <<
                      get_arg_count();
            return false;
        }

        return test(location);
    }

    template<typename... Args>
    class FunctionIdentifierInternalNode<void, Args...> : public FunctionIdentifierNodeI {
    public:
        FunctionIdentifierInternalNode(std::vector<size_t> arg_sizes,
                                       std::tuple<Args...> preargs,
                                       std::tuple<Args...> postargs);

        FunctionIdentifierInternalNode(const FunctionIdentifierInternalNode &other);

        virtual bool test(uintptr_t location) override;

        virtual bool test_arity(uintptr_t location, arg_count_t arity) override;

        virtual arg_count_t get_arg_count() override;

    protected:
        std::tuple<Args...> preargs_;
        std::tuple<Args...> postargs_;
        std::vector<size_t> arg_sizes_;
    };


    template<typename... Args>
    FunctionIdentifierInternalNode<void, Args...>::FunctionIdentifierInternalNode(std::vector<size_t> arg_sizes,
                                                                                  std::tuple<Args...> preargs,
                                                                                  std::tuple<Args...> postargs):
            FunctionIdentifierNodeI(""), arg_sizes_(arg_sizes), preargs_(preargs), postargs_(postargs) {
    }

    template<typename... Args>
    arg_count_t FunctionIdentifierInternalNode<void, Args...>::get_arg_count() { return sizeof...(Args); }

    template<typename... Args>
    bool FunctionIdentifierInternalNode<void, Args...>::test_arity(uintptr_t location, arg_count_t arity) {
        if (arity != get_arg_count()) {
            LOG_DEBUG << std::hex << location << std::dec << " has arity " << arity << " and does not match " <<
                      get_arg_count();
            return false;
        }

        return test(location);
    }

    template<typename... Args>
    bool FunctionIdentifierInternalNode<void, Args...>::test(uintptr_t location) {
        pid_t pid = fork();
        if (pid == 0) {
            bool is_equiv = false;
            std::function<void(Args...)> func = reinterpret_cast<void (*)(
                    Args...)>(location);
            std::apply(func, preargs_);

            if constexpr(sizeof...(Args) > 0) {
                is_equiv = arg_checker<0, Args...>::check_args(arg_sizes_, preargs_, postargs_);
            }

            exit(is_equiv == true);
        } else {
            int status = 0;
            waitpid(pid, &status, 0);
            return (WIFEXITED(status) && WEXITSTATUS(status) == 1);
        }
    }

    template<typename... Args>
    FunctionIdentifierInternalNode<void, Args...>::FunctionIdentifierInternalNode(const
                                                                                  FunctionIdentifierInternalNode<void, Args...>
                                                                                  &other) : FunctionIdentifierNodeI(
            "") {
        preargs_ = other.preargs_;
        postargs_ = other.postargs_;
        arg_sizes_ = other.arg_sizes_;
    }
}

#endif //FOSBIN_TESTNODE_H
