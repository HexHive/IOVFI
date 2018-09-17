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

    protected:
        void* testPtr;
        char* testStr;
        int testInt;
        double testDbl;

        virtual void create_testcases();
    };
}


#endif //FOSBIN_FULLSLEUTHTEST_H
