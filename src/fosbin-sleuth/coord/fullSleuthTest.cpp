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

fbf::FullSleuthTest::FullSleuthTest(fs::path descriptor, size_t strLen, size_t ptrLen, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    /* Avoid testInt values */
    std::uniform_int_distribution<uint8_t> charRand(MAX_ARGUMENTS + 2, 0xfe);
    std::uniform_real_distribution<double> dblRand(std::numeric_limits<double>::min(),
                                                   std::numeric_limits<double>::max());
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine re(seed);

    for (size_t i = 0; i < MAX_ARGUMENTS; i++) {
        testInts.push_back(i + 1);
        testDbls.push_back(dblRand(re));

        testStrs.push_back((char *) std::malloc(strLen));
        testPtrs.push_back(ProtectedBuffer(ptrLen));

        for (size_t j = 0; j < strLen; j++) {
            /* Printable characters */
            char randChar = '!' + charRand(re) % ('~' - '!');
            testStrs[i][j] = randChar;
        }

        ProtectedBuffer buf = testPtrs[i];
        for (size_t j = 0; j < ptrLen; j++) {
            buf[j] = charRand(re);
        }
    }

    create_testcases();
}

fbf::FullSleuthTest::~FullSleuthTest() {
    for (char *str : testStrs) {
        std::free(str);
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
            while (std::getline(ss, tok, ' ')) {
                if (!tok.empty()) {
                    args.push_back(tok);
                }
            }

            if (min_arg_counts.find(it.first) == min_arg_counts.end()) {
                min_arg_counts[it.first] = args.size();
                std::vector<std::shared_ptr<fbf::TestRun>> v;
                v.push_back(valid_args);
                successes[it.first] = v;
            } else if (min_arg_counts[it.first] == args.size()) {
                successes[it.first].push_back(valid_args);
            } else if (min_arg_counts[it.first] > args.size()) {
                successes[it.first].clear();
                successes[it.first].push_back(valid_args);
                min_arg_counts[it.first] = args.size();
            }
        }
    }

    for (auto it : successes) {
        if(binDesc_.isSharedLibrary()) {
            const std::string& sym = binDesc_.getSym(it.first);
            o << sym << ": ";
        } else {
            o << "0x" << std::hex <<
              it.first << std::dec <<
              ": ";
        }
        for (auto arg_types : it.second) {
            if (arg_types->get_test_name().empty() || arg_types->get_test_name() == "<>") {
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

#include "TestCases.inc"
    }
}
