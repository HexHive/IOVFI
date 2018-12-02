//
// Created by derrick on 10/15/18.
//

#ifndef FOSBIN_TESTNODE_H
#define FOSBIN_TESTNODE_H

#include <fosbin-config.h>
#include <initializer_list>
#include <tuple>
#include <sys/wait.h>
#include <iTestCase.h>
#include <signal.h>
#include <TupleHelpers.h>
#include <identifiers/functionIdentifierNodeI.h>

#define TIMEOUT_INTERNAL    100

namespace fbf {
    static void sig_handler(int sig) {
        kill(getpid(), SIGKILL);
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

        virtual bool test_arity(uintptr_t location, arity_t arity) override;

        virtual arity_t get_arg_count() override;

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
        //signal(SIGALRM, sig_handler);
        //ualarm(TIMEOUT_INTERNAL, 0);
    }

    template<typename R, typename... Args>
    bool FunctionIdentifierInternalNode<R, Args...>::test(uintptr_t location) {
        LOG_DEBUG << "Calling function with " << print_args(preargs_) << " Expecting " << retVal_;
        pid_t pid = test_fork();
        if (pid == 0) {
            bool is_equiv = true;
            std::function<R(Args...)> func = reinterpret_cast<R(*)(
                    Args...)>(location);
            //LOG_DEBUG << "Calling function with " << print_args(preargs_) << " Expecting " << retVal_;
            set_signals();
            R retVal = std::apply(func, preargs_);
            if(retVal) {
              //  LOG_DEBUG << "Function returned " << retVal;
            } else {
                //LOG_DEBUG << "Function returned nullptr";
            }

            if constexpr (std::is_pointer_v<R>) {
                int test = 0;
                if(retVal && retVal_) {
                    test = std::strncmp(retVal, retVal_, retSize_);
                } else {
                    if(retVal && !retVal_) {
                        test = 1;
                    } else if(!retVal && retVal_ && std::strcmp(retVal_, "") != 0) {
                        test = 1;
                    }
                }
                //LOG_DEBUG << "Comparing " << retSize_ << " bytes resulted in " << test;
                is_equiv = (test == 0);
            } else {
                R diff = retVal - retVal_;
                if (diff < 0) {
                    diff *= -1;
                }
                is_equiv = (diff <= 0.0000000001l);
            }

            //LOG_DEBUG << "return values are " << (is_equiv ? "" : "NOT ") << "the same";

            if constexpr(sizeof...(Args) > 0) {
                if(is_equiv) {
                    is_equiv &= check_tuple_args(preargs_, postargs_, arg_sizes_);
                }
            }

            //LOG_DEBUG << std::hex << location << std::dec << " is returning " << (is_equiv ? "PASS" : "FAIL");

            exit(is_equiv == true ? ITestCase::PASS : ITestCase::FAIL);
        } else if(pid > 0) {
            int status = 0;
            LOG_DEBUG << "Process " << getpid() << " is waiting on " << pid;
            waitpid(pid, &status, 0);
            if(!WIFEXITED(status)) {
                LOG_DEBUG << "Function faulted";
            } else if(WEXITSTATUS(status) != ITestCase::PASS) {
                LOG_DEBUG << "Function exited with exit code " << WEXITSTATUS(status);
            }
            return (WIFEXITED(status) && WEXITSTATUS(status) == ITestCase::PASS);
        } else {
            throw std::runtime_error("Could not fork!");
        }
    }

    template<typename R, typename... Args>
    arity_t FunctionIdentifierInternalNode<R, Args...>::get_arg_count() { return sizeof...(Args); }

    template<typename R, typename... Args>
    bool FunctionIdentifierInternalNode<R, Args...>::test_arity(uintptr_t location, arity_t arity) {
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

        virtual bool test_arity(uintptr_t location, arity_t arity) override;

        virtual arity_t get_arg_count() override;

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
    arity_t FunctionIdentifierInternalNode<void, Args...>::get_arg_count() { return sizeof...(Args); }

    template<typename... Args>
    bool FunctionIdentifierInternalNode<void, Args...>::test_arity(uintptr_t location, arity_t arity) {
        if (arity != get_arg_count()) {
            LOG_DEBUG << std::hex << location << std::dec << " has arity " << arity << " and does not match " <<
                      get_arg_count();
            return false;
        }

        return test(location);
    }

    template<typename... Args>
    bool FunctionIdentifierInternalNode<void, Args...>::test(uintptr_t location) {
        LOG_DEBUG << "Calling void function with " << print_args(preargs_);
        pid_t pid = test_fork();
        if (pid == 0) {
            bool is_equiv = false;
            std::function<void(Args...)> func = reinterpret_cast<void (*)(
                    Args...)>(location);
            //LOG_DEBUG << "Calling void function with " << print_args(preargs_);
            set_signals();
            std::apply(func, preargs_);
            //LOG_DEBUG << "Function returned";

            if constexpr(sizeof...(Args) > 0) {
                is_equiv = check_tuple_args(preargs_, postargs_, arg_sizes_);
            }

            //LOG_DEBUG << std::hex << location << std::dec
            //        << " is returning " << (is_equiv ? "PASS" : "FAIL");

            exit(is_equiv == true ? ITestCase::PASS : ITestCase::FAIL);
        } else if(pid > 0){
            int status = 0;
            LOG_DEBUG << "Process " << getpid() << " is waiting on " << pid;
            waitpid(pid, &status, 0);
            if(!WIFEXITED(status)) {
                LOG_DEBUG << "Function faulted";
            } else if(WEXITSTATUS(status) != ITestCase::PASS) {
                LOG_DEBUG << "Function exited with exit code " << WEXITSTATUS(status);
            }
            return (WIFEXITED(status) && WEXITSTATUS(status) == fbf::ITestCase::PASS);
        } else {
            throw std::runtime_error("Could not fork!");
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
        //signal(SIGALRM, sig_handler);
        //ualarm(TIMEOUT_INTERNAL, 0);
    }
}

#endif //FOSBIN_TESTNODE_H
