//
// Created by derrick on 11/19/18.
//

#ifndef FOSBIN_FULLFUZZTEST_H
#define FOSBIN_FULLFUZZTEST_H

#include <fullTest.h>
#include <fuzz/FosbinFuzzer.h>
#include <map>

namespace fbf {
    class FullFuzzTest : public FullTest {
    public:
        FullFuzzTest(fs::path descriptor, fs::path aritys, uint32_t thread_count = 1);
        ~FullFuzzTest();

        virtual void create_testcases();

        const static size_t MAX_ARGUMENTS;

    protected:
        std::map<arity_t, std::vector<std::shared_ptr<ITestCase>>> fuzzers;
    };
}


#endif //FOSBIN_FULLFUZZTEST_H
