//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_FULLTEST_H
#define FOSBIN_FLOP_FULLTEST_H

#include <fosbin-flop.h>
#include "fullTest.h"

namespace fs = std::experimental::filesystem;

namespace fbf {
    class FullIdentifierTest : public FullTest {
    public:
        FullIdentifierTest(fs::path descriptor, uint32_t thread_count = 1);

        virtual ~FullIdentifierTest();

    protected:
        virtual void create_testcases();

        std::vector<void*> buffers_;
    };
}

#endif //FOSBIN_FLOP_FULLTEST_H
