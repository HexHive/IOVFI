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
        ArgumentTestCase(uintptr_t location,
                std::tuple<Args...> args,
                std::vector<std::string> argTypes);
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
        std::vector<std::string> argTypes_;
    };

    template<typename R, typename... Args>
    fbf::ArgumentTestCase<R, Args...>::ArgumentTestCase(uintptr_t location,
            std::tuple<Args...> args,
            std::vector<std::string> argTypes)
            : location_(location), args_(args), argTypes_(argTypes)
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
        if(argTypes_.size() == 0) {
            return "<>";
        }
        std::stringstream s;
        s << "<";
        for(auto type : argTypes_) {
            s << type << " ";
        }
        s << ">";

        return s.str().erase(s.str().size() - 2, 1);
    }
}

#endif //FOSBIN_ARGUMENTTESTCASE_H