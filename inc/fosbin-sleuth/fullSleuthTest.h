//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_FULLSLEUTHTEST_H
#define FOSBIN_FULLSLEUTHTEST_H

#include "fullTest.h"
#include "protectedBuffer.h"
#include <vector>

namespace fbf {
    class FullSleuthTest : public FullTest {
    public:
        FullSleuthTest(fs::path descriptor, size_t strLen, size_t ptrLen, uint32_t thread_count = 1);
        FullSleuthTest(const FullSleuthTest& other);

        virtual ~FullSleuthTest();

        virtual void output(std::ostream &o) override;

        const static int MAX_ARGUMENTS = 8;

    protected:
        std::vector<ProtectedBuffer> testPtrs;
        std::vector<char *> testStrs;
        std::vector<int> testInts;
        std::vector<double> testDbls;

        virtual void create_testcases() override;
    };
}


#endif //FOSBIN_FULLSLEUTHTEST_H
