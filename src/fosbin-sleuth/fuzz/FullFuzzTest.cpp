//
// Created by derrick on 11/19/18.
//

#include <fuzz/FullFuzzTest.h>
#include <fosbin-sleuth/fuzz/FullFuzzTest.h>
#include <fosbin-sleuth/fullArityTest.h>

const size_t fbf::FullFuzzTest::MAX_ARGUMENTS = fbf::FullArityTest::MAX_ARGUMENTS;

fbf::FullFuzzTest::FullFuzzTest(fs::path descriptor, fs::path aritys, uint32_t thread_count) : FullTest(descriptor,
                                                                                                           thread_count) {
    binDesc_.parse_aritys(aritys);
}

fbf::FullFuzzTest::~FullFuzzTest() = default;

void fbf::FullFuzzTest::create_testcases() {
    /* TODO: Adapt python script to generate these class definitions */
    std::shared_ptr<fbf::FosbinFuzzer<double, double>> fuzzer0 =
            std::make_shared<fbf::FosbinFuzzer<double, double>>(binDesc_, 0.0);
    fuzzers[fuzzer0->get_arity()].push_back(fuzzer0);

    for(uintptr_t loc : binDesc_.getOffsets()) {
        const LofSymbol &sym = binDesc_.getSym(loc);
        for(std::shared_ptr<fbf::ITestCase> arity_fuzzer : fuzzers[sym.arity]) {
            testRuns_.push_back(std::make_shared<fbf::TestRun>(arity_fuzzer, loc));
        }
    }

}
