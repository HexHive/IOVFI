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

namespace fbf {
#define MAX_ARG_COUNT   8
#define STR_LEN         48
#define PTR_LEN         1024
#define DEFAULT_INT     1
#define DEFAULT_DOUBLE  2.0

    template<typename R, typename... Args>
    class ArgumentTestCase {
    public:
        ArgumentTestCase();
        virtual ~ArgumentTestCase();

        template< typename U = std::tuple<Args...> >
        std::enable_if_t<(std::tuple_size<U>::value > 0)>
        test(uintptr_t location, size_t nargs = sizeof...(Args)) {
            std::function<R(Args...)> func = reinterpret_cast<R(*)(Args...)>(location);
            std::tuple<Args...> t;

            if(std::is_same< decltype(testInt), typename std::tuple_element<0, std::tuple<Args...>>::type >::value)  {
                std::get<0>(t) = testInt;
            } else if(std::is_same< decltype(testDbl), typename std::tuple_element<0, std::tuple<Args...>>::type >::value) {
                std::get<0>(t) = testDbl;
            }

            if(nargs >= 1) {
                if(std::is_same< decltype(testInt), typename std::tuple_element<1, std::tuple<Args...>>::type >::value)  {
                    std::get<1>(t) = testInt;
                } else if(std::is_same< decltype(testDbl), typename std::tuple_element<1, std::tuple<Args...>>::type >::value) {
                    std::get<1>(t) = testDbl;
                }
            }

            execute(func, t);
        }

        template< typename U = std::tuple<Args...> >
        std::enable_if_t<(std::tuple_size<U>::value == 0)>
        test(uintptr_t location) {
            std::function<R()> func = reinterpret_cast<R(*)()>(location);
            std::tuple<> t;

            execute(func, t);
            std::cout << "void function called" << std::endl;
        }

    protected:
        int testInt;
        double testDbl;
        char* testStr;
        void* testPtr;

        bool testPasses;
        int errno_before;

        void precall();
        void postcall();

        void execute(std::function<void(Args...)>& func, std::tuple<Args...>& args) {
            precall();
            std::apply(func, args);
            postcall();
        }
    };

    template<typename R, typename... Args>
    fbf::ArgumentTestCase<R, Args...>::ArgumentTestCase() :
        testInt(DEFAULT_INT), testDbl(DEFAULT_DOUBLE), testPasses(false), errno_before(0)
    {
        testStr = (char*)std::malloc(STR_LEN);
        testPtr = std::malloc(PTR_LEN);
    }

    template<typename R, typename... Args>
    fbf::ArgumentTestCase<R, Args...>::~ArgumentTestCase() {
        if(testStr) {
            std::free(testStr);
        }

        if(testPtr) {
            std::free(testPtr);
        }
    }

    template<typename R, class... Args>
    void fbf::ArgumentTestCase<R, Args...>::postcall() {
        testPasses = (errno == errno_before);
    }

    template<typename R, class... Args>
    void fbf::ArgumentTestCase<R, Args...>::precall() {
        errno_before = errno;
    }

//    template<typename R, class... Args>
//    R fbf::ArgumentTestCase<R, Args...>::execute(std::function<R(Args...)> &func, std::tuple<Args...> &args) {
//        precall();
//        if(!std::is_void<R>::value) {
//            R result = std::apply(func, args);
//            postcall();
//            return result;
//        } else {
//            std::apply(func, args);
//            postcall();
//        }
//    }
}

#endif //FOSBIN_ARGUMENTTESTCASE_H