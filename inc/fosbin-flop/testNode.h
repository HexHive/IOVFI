//
// Created by derrick on 10/15/18.
//

#ifndef FOSBIN_TESTNODE_H
#define FOSBIN_TESTNODE_H

#include <fosbin-config.h>
#include <vector>
#include <any>
#include <tuple>

namespace fbf {
    typedef arg_count_t size_t;

    template<typename R, typename... Args>
    class TestNode {
    public:
        TestNode(R& retValue, Args... &args);
        bool test(uintptr_t location);
        arg_count_t getArgCount();

    protected:
        R& retVal_;
        std::tuple<Args> args_;
    };


    template<typename R, typename... Args>
    arg_count_t TestNode<R, Args>::getArgCount() { return sizeof...(Args); }

    template<typename R, typename... Args>
    TestNode<R, Args>::TestNode(R& retVal, Args... &args) {
        args_ = std::make_tuple(args);
        retVal_ = retVal;
    }

    template<typename R, typename... Args>
    bool test(uintptr_t location) {
        std::function<R(Args)> func = reinterpret_cast<R(*)(Args)>(location);
        R retVal = std::apply(func, args_);
        return retVal == retVal_;
    }
}


#endif //FOSBIN_TESTNODE_H
