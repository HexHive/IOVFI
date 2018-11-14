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
#include <iTestCase.h>
#include "functionIdentifierNodeI.h"
#include <signal.h>

#define TIMEOUT_INTERNAL    100

namespace fbf {
    static void sig_handler(int sig) {
        exit(ITestCase::FAIL);
    }

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

    template<typename Tup, size_t... I>
    void print_arg(std::ostream& out, const Tup& tup, std::index_sequence<I...>) {
        out << "(";
        (..., (out << (I == 0 ? "" : ", ") << std::hex << std::get<I>(tup)));
        out << ")";
    }

    template<typename... T>
    std::string print_args(const std::tuple<T...>& tup) {
        std::stringstream out;
        print_arg(out, tup, std::make_index_sequence<sizeof...(T)>());
        return out.str();
    }


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

        void set_signals();
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
    void FunctionIdentifierInternalNode<R, Args...>::set_signals() {
        signal(SIGALRM, sig_handler);
        ualarm(TIMEOUT_INTERNAL, 0);
    }

    template<typename R, typename... Args>
    bool FunctionIdentifierInternalNode<R, Args...>::test(uintptr_t location) {
        pid_t pid = fork();
        if (pid == 0) {
//            set_signals();
            bool is_equiv = true;
            std::function<R(Args...)> func = reinterpret_cast<R(*)(
                    Args...)>(location);
            LOG_DEBUG << "Calling function with " << print_args(preargs_) << " Expecting " << retVal_;
            R retVal = std::apply(func, preargs_);
            if constexpr (std::is_pointer_v<R>) {
                is_equiv = (std::memcmp(retVal, retVal_, retSize_) == 0);
            } else {
                R diff = retVal - retVal_;
                if(diff < 0) {
                    diff *= -1;
                }
                is_equiv = (diff <= 0.00000001l);
            }

            if constexpr(sizeof...(Args) > 0) {
                is_equiv &= arg_checker<0, Args...>::check_args(arg_sizes_, preargs_, postargs_);
            }

            exit(is_equiv == true ? ITestCase::PASS : ITestCase::FAIL);
        } else {
            int status = 0;
            waitpid(pid, &status, 0);
            return (WIFEXITED(status) && WEXITSTATUS(status) == ITestCase::PASS);
        }
    }

    template<typename R, typename... Args>
    arg_count_t FunctionIdentifierInternalNode<R, Args...>::get_arg_count() { return sizeof...(Args); }

    template<typename R, typename... Args>
    bool FunctionIdentifierInternalNode<R, Args...>::test_arity(uintptr_t location, arg_count_t arity) {
        if (arity != get_arg_count()) {
            LOG_TRACE << std::hex << location << std::dec << " has arity " << arity << " and does not match " <<
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
        void set_signals();
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
            LOG_TRACE << std::hex << location << std::dec << " has arity " << arity << " and does not match " <<
                      get_arg_count();
            return false;
        }

        return test(location);
    }

    template<typename... Args>
    bool FunctionIdentifierInternalNode<void, Args...>::test(uintptr_t location) {
        pid_t pid = fork();
        if (pid == 0) {
//            set_signals();
            bool is_equiv = false;
            std::function<void(Args...)> func = reinterpret_cast<void (*)(
                    Args...)>(location);
            LOG_DEBUG << "Calling void function with " << print_args(preargs_);
            std::apply(func, preargs_);

            if constexpr(sizeof...(Args) > 0) {
                is_equiv = arg_checker<0, Args...>::check_args(arg_sizes_, preargs_, postargs_);
            }

            exit(is_equiv == true ? ITestCase::PASS : ITestCase::FAIL);
        } else {
            int status = 0;
            waitpid(pid, &status, 0);
            return (WIFEXITED(status) && WEXITSTATUS(status) == fbf::ITestCase::PASS);
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

    template<typename... Args>
    void FunctionIdentifierInternalNode<void, Args...>::set_signals() {
        signal(SIGALRM, sig_handler);
        ualarm(TIMEOUT_INTERNAL, 0);
    }
}

#endif //FOSBIN_TESTNODE_H
