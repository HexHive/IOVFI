//
// Created by derrick on 9/17/18.
//

#include <fosbin-sleuth/fullSleuthTest.h>
#include <fosbin-sleuth/argumentTestCase.h>

#include "fosbin-sleuth/fullSleuthTest.h"

#include <vector>
#include <map>
#include <cstring>
#include <random>
#include <limits>
#include <iterator>
#include <chrono>
#include <unistd.h>
#include <sys/mman.h>

fbf::FullSleuthTest::FullSleuthTest(fs::path descriptor, int i, double d, size_t strLen, size_t ptrLen) :
        FullTest(descriptor) {
    std::uniform_int_distribution<int> intRand(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());
    std::uniform_real_distribution<double> dblRand(std::numeric_limits<double>::min(),
                                                   std::numeric_limits<double>::max());
    int page_size = getpagesize();

    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine re(seed);

    for (size_t i = 0; i < MAX_ARGUMENTS; i++) {
        testInts[i] = i + 1;
        testDbls[i] = dblRand(re);

        /* Separate allocated pointers by guard pages */
        void* ptr = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE, 0, 0);
        testPtrs[i] = mmap((char*)ptr + page_size, ptrLen, PROT_READ | PROT_WRITE, MAP_PRIVATE, 0, 0);
        mmap((char*)testPtrs[i] + ptrLen, page_size, PROT_NONE, MAP_PRIVATE, 0, 0);
        
        testStrs[i] = (char *) std::malloc(strLen);

        for (size_t j = 0; j < strLen; j++) {
            /* Printable characters */
            char randChar = '!' + intRand(re) % ('~' - '!');
            testStrs[i][j] = randChar;
        }

        for (size_t j = 0; j < ptrLen; j++) {
            ((char*)testPtrs[i])[j] = (char)intRand(re);
        }
    }

    create_testcases();
}

fbf::FullSleuthTest::~FullSleuthTest() {
    for (size_t i = 0; i < MAX_ARGUMENTS; i++) {
        if (testPtrs[i]) {
            std::free(testPtrs[i]);
        }
        if (testStrs[i]) {
            std::free(testStrs[i]);
        }
    }
}

void fbf::FullSleuthTest::output(std::ostream &o) {
    std::map<uintptr_t, std::vector<std::shared_ptr<fbf::TestRun>>> candidates;
    std::map<uintptr_t, std::vector<std::shared_ptr<fbf::TestRun>>> successes;
    std::map<uintptr_t, int> min_arg_counts;

    for (std::shared_ptr<fbf::TestRun> test : testRuns_) {
        if (test->get_result() == fbf::ITestCase::PASS) {
            if (candidates.find(test->get_offset()) == candidates.end()) {
                std::vector<std::shared_ptr<fbf::TestRun>> v;
                v.push_back(test);
                candidates[test->get_offset()] = v;
            } else {
                candidates[test->get_offset()].push_back(test);
            }
        }
    }


    for (auto it : candidates) {
        for (auto valid_args : it.second) {
            std::stringstream ss(valid_args->get_test_name());
            std::string tok;
            std::vector<std::string> args;
            while(std::getline(ss, tok, ' ')) {
                if(!tok.empty()) {
                    args.push_back(tok);
                }
            }

//            if(min_arg_counts.find(it.first) == min_arg_counts.end()) {
//                min_arg_counts[it.first] = args.size();
//                std::vector<std::shared_ptr<fbf::TestRun>> v;
//                v.push_back(valid_args);
//                successes[it.first] = v;
//            } else if(min_arg_counts[it.first] == args.size()) {
//                successes[it.first].push_back(valid_args);
//            } else if(min_arg_counts[it.first] > args.size()) {
//                successes[it.first].clear();
//                successes[it.first].push_back(valid_args);
//                min_arg_counts[it.first] = args.size();
//            }
            if(min_arg_counts.find(it.first) == min_arg_counts.end()) {
                min_arg_counts[it.first] = args.size();
                std::vector<std::shared_ptr<fbf::TestRun>> v;
                v.push_back(valid_args);
                successes[it.first] = v;
            } else {
                successes[it.first].push_back(valid_args);
            }
        }
    }

    for (auto it : successes) {
        o << "0x" << std::hex <<
            it.first << std::dec <<
            ": ";
        for(auto arg_types : it.second) {
            if(arg_types->get_test_name().empty() || arg_types->get_test_name() == "<>") {
                o << "< void >";
            } else {
                o << "< " << arg_types->get_test_name() << " > ";
            }
            o << " ";
        }
        o << std::endl;
    }
}

void fbf::FullSleuthTest::create_testcases() {
    for (uintptr_t offset : binDesc_.getOffsets()) {
        uintptr_t location = compute_location(offset);
        {
            std::tuple<uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t> t;
            std::vector<std::string> l;

            std::get<0>(t) = (uintptr_t)-1;
            std::get<1>(t) = (uintptr_t)-1;
            std::get<2>(t) = (uintptr_t)-1;
            std::get<3>(t) = (uintptr_t)-1;
            std::get<4>(t) = (uintptr_t)-1;
            std::get<5>(t) = (uintptr_t)-1;
            std::get<6>(t) = (uintptr_t)-1;
            std::get<7>(t) = (uintptr_t)-1;

            std::shared_ptr<fbf::ArgumentTestCase<void *, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t>> v =
                    std::make_shared<fbf::ArgumentTestCase<void *, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t>>(location, t, l);
            testRuns_.push_back(std::make_shared<fbf::TestRun>(v, offset));
        }

#include "TestCases.inc"

    }
}
