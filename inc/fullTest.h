//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_FULLTEST_H
#define FOSBIN_FULLTEST_H
#include <vector>
#include "binaryDescriptor.h"
#include "testRun.h"
#include "CTPL/ctpl.h"
#include <cstddef>
#include <limits>

namespace fbf {
    class FullTest {
    protected:
        std::vector<std::shared_ptr<fbf::TestRun>> testRuns_;
        BinaryDescriptor binDesc_;
        ctpl::thread_pool pool_;
        uint32_t thread_count_;

        virtual void create_testcases() = 0;
        virtual uintptr_t compute_location(uintptr_t offset);

        uint64_t getRandLong();

    public:
        FullTest(fs::path descriptor, uint32_t thread_count);
        FullTest(fs::path descriptor, fs::path syscall_mapping, uint32_t thread_count);
        FullTest(const FullTest& other);
        ~FullTest();

        FullTest& operator=(const FullTest& other);
        virtual void run();
        virtual void output(std::ostream& out);

    private:
            std::uniform_int_distribution<uint64_t> rand_int;
            std::default_random_engine re;
            void seed_rand();
    };
}


#endif //FOSBIN_FULLTEST_H
