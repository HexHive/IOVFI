//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_FULLSLEUTHTEST_H
#define FOSBIN_FULLSLEUTHTEST_H

#include "fullTest.h"

namespace fbf {
    class FullSleuthTest : public FullTest {
    public:
        FullSleuthTest(fs::path descriptor, int i, double d, size_t strLen, size_t ptrLen);

        virtual ~FullSleuthTest();
        virtual void output(std::ostream& o) override;

        const static int MAX_ARGUMENTS = 8;

    protected:
        void* testPtrs[MAX_ARGUMENTS];
        char* testStrs[MAX_ARGUMENTS];
        int testInts[MAX_ARGUMENTS];
        double testDbls[MAX_ARGUMENTS];

        virtual void create_testcases() override;
    };
}


#endif //FOSBIN_FULLSLEUTHTEST_H
