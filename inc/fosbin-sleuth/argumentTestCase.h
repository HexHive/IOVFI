//
// Created by derrick on 9/14/18.
//

#ifndef FOSBIN_ARGUMENTTESTCASE_H
#define FOSBIN_ARGUMENTTESTCASE_H

#include <cstdint>
#include <functional>
#include <iostream>
#include <tuple>
#include <cassert>
#include <sstream>
#include <cerrno>
#include <cstring>
#include "iTestCase.h"

namespace fbf {
    template<typename R, typename... Args>
    class ArgumentTestCase : public ITestCase {
    public:
        ArgumentTestCase(uintptr_t location,
                         std::tuple<Args...> args,
                         std::vector<std::string> argTypes, BinaryDescriptor &binDesc);

        virtual ~ArgumentTestCase();

        const std::string get_test_name();

        int run_test();

        virtual uint64_t get_value();

    protected:
        uintptr_t location_;
        std::tuple<Args...> args_;

        BinaryDescriptor &binDesc_;

        R returnValue_;

        bool testPasses_;
        int errno_before_;

        void precall();

        void postcall();

        std::vector<std::string> argTypes_;
    };

    template<typename R, typename... Args>
    fbf::ArgumentTestCase<R, Args...>::ArgumentTestCase(uintptr_t location,
                                                        std::tuple<Args...> args,
                                                        std::vector<std::string> argTypes, BinaryDescriptor &binDesc)
            : ITestCase(), location_(location), args_(args), argTypes_(argTypes), binDesc_(binDesc) {
        std::memset(&returnValue_, (char)binDesc_.getIdentifier(), sizeof(returnValue_));
    }

    template<typename R, typename... Args>
    uint64_t fbf::ArgumentTestCase<R, Args...>::get_value() {
        return (uint64_t)returnValue_;
    }

    template<typename R, typename... Args>
    int fbf::ArgumentTestCase<R, Args...>::run_test() {
        std::function<R(Args...)> func = reinterpret_cast<R(*)(Args...)>(location_);
        precall();
        try {
            returnValue_ = std::apply(func, args_);
        } catch (std::exception &e) {
            return fbf::ITestCase::FAIL;
        }
        postcall();
        return testPasses_ == true ? fbf::ITestCase::PASS : fbf::ITestCase::NON_CRASHING;
    }

    template<typename R, typename... Args>
    fbf::ArgumentTestCase<R, Args...>::~ArgumentTestCase() {}

    template<typename R, class... Args>
    void fbf::ArgumentTestCase<R, Args...>::postcall() {
        testPasses_ = (binDesc_.getErrno() == errno_before_);
    }

    template<typename R, class... Args>
    void fbf::ArgumentTestCase<R, Args...>::precall() {
        errno_before_ = binDesc_.getErrno();
    }

    template<typename R, class... Args>
    const std::string fbf::ArgumentTestCase<R, Args...>::get_test_name() {
        if (argTypes_.size() == 0) {
            return "<>";
        }
        std::stringstream s;
        for (auto type : argTypes_) {
            s << type << " ";
        }

        return s.str().erase(s.str().size() - 1, 1);
    }
}

#endif //FOSBIN_ARGUMENTTESTCASE_H
