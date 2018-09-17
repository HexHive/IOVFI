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
#include "iTestCase.h"

namespace fbf {
    template<typename R, typename... Args>
    class ArgumentTestCase : public ITestCase {
    public:
        ArgumentTestCase(uintptr_t location, std::tuple<Args...> args);
        virtual ~ArgumentTestCase();

        const std::string get_test_name();
        int run_test();

    protected:
        uintptr_t location_;
        std::tuple<Args...> args_;

        bool testPasses_;
        int errno_before_;

        void precall();
        void postcall();
    };

    template<typename R, typename... Args>
    fbf::ArgumentTestCase<R, Args...>::ArgumentTestCase(uintptr_t location, std::tuple<Args...> args)
            : location_(location), args_(args)
    {

    }

    template<typename R, typename... Args>
    int fbf::ArgumentTestCase<R, Args...>::run_test() {
        std::function<R(Args...)> func = reinterpret_cast<R(*)(Args...)>(location_);
        precall();
        std::apply(func, args_);
        postcall();
        return testPasses_ == true ? fbf::ITestCase::PASS : fbf::ITestCase::FAIL;
    }

    template<typename R, typename... Args>
    fbf::ArgumentTestCase<R, Args...>::~ArgumentTestCase() { }

    template<typename R, class... Args>
    void fbf::ArgumentTestCase<R, Args...>::postcall() {
        testPasses_ = (errno == errno_before_);
    }

    template<typename R, class... Args>
    void fbf::ArgumentTestCase<R, Args...>::precall() {
        errno_before_ = errno;
    }

    template<typename R, class... Args>
    const std::string fbf::ArgumentTestCase<R, Args...>::get_test_name() {
        std::stringstream s;
        size_t arg = sizeof...(Args);
        s << typeid(args_).name();
        return s.rdbuf()->str();
    }
}

#endif //FOSBIN_ARGUMENTTESTCASE_H