//
// Created by derrick on 9/14/18.
//

#ifndef FOSBIN_VOIDTESTCASE_H
#define FOSBIN_VOIDTESTCASE_H
#include <argumentTestCase.h>

namespace fbf {
    template<typename R>
    class EmptyTestCase : public fbf::ArgumentTestCase<R> {
    public:
        EmptyTestCase();
    };
}

template<typename R>
fbf::EmptyTestCase<R>::EmptyTestCase() : ArgumentTestCase<R>() { }

#endif //FOSBIN_VOIDTESTCASE_H
