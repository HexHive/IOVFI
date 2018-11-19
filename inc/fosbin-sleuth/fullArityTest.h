//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_FULLSLEUTHTEST_H
#define FOSBIN_FULLSLEUTHTEST_H

#include "fullTest.h"
#include "protectedBuffer.h"
#include <vector>

namespace fbf {
    class FullArityTest : public FullTest {
    public:
        FullArityTest(fs::path descriptor, size_t strLen, size_t ptrLen, uint32_t thread_count = 1);
        FullArityTest(fs::path descriptor, fs::path syscall_mapping, size_t strLen, size_t ptrLen, uint32_t thread_count = 1);
        FullArityTest(const FullArityTest& other);

        virtual ~FullArityTest();

        virtual void output(std::ostream &o) override;

        const static int MAX_ARGUMENTS = 6;

    protected:
        std::vector<ProtectedBuffer> testPtrs;
        std::vector<char *> testStrs;
        std::vector<int> testInts;
        std::vector<double> testDbls;

        virtual void create_testcases() override;

    private:
        void init(size_t strLen, size_t ptrLen);
    };
}


#endif //FOSBIN_FULLSLEUTHTEST_H
