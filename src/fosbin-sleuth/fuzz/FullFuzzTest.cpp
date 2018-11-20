//
// Created by derrick on 11/19/18.
//

#include <fuzz/FullFuzzTest.h>
#include <fosbin-sleuth/fuzz/FullFuzzTest.h>
#include <fosbin-sleuth/fullArityTest.h>
#include <cstdlib>

const size_t fbf::FullFuzzTest::MAX_ARGUMENTS = fbf::FullArityTest::MAX_ARGUMENTS;

fbf::FullFuzzTest::FullFuzzTest(fs::path descriptor, fs::path aritys, uint32_t thread_count) : FullTest(descriptor,
                                                                                                           thread_count) {
    binDesc_.parse_aritys(aritys);
}

fbf::FullFuzzTest::~FullFuzzTest() {
    for(void* buf : buffers) {
        std::free(buf);
    }
}

void fbf::FullFuzzTest::create_testcases() {
    /* TODO: Adapt python script to generate these class definitions */
    void* buf0 = create_buffer(ITestCase::POINTER_SIZE);
    void* buf1 = create_buffer(ITestCase::POINTER_SIZE);
    std::shared_ptr<fbf::FosbinFuzzer<void, double, void*, void*>> fuzzer0 =
            std::make_shared<fbf::FosbinFuzzer<void, double, void*, void*>>(binDesc_, std::make_tuple(0.0, buf0, buf1));
    fuzzers[fuzzer0->get_arity()].push_back(fuzzer0);

    for(uintptr_t loc : binDesc_.getOffsets()) {
        const LofSymbol &sym = binDesc_.getSym(loc);
        for(std::shared_ptr<fbf::ITestCase> arity_fuzzer : fuzzers[sym.arity]) {
            testRuns_.push_back(std::make_shared<fbf::TestRun>(arity_fuzzer, loc));
        }
    }
}

void *fbf::FullFuzzTest::create_buffer(size_t size) {
    void* ret = std::malloc(size);
    if(!ret) {
        throw std::runtime_error("Could not allocate fuzzing buffer");
    }

    /* Make each uintptr_t-sized area point to the immediate next
     * uintptr_t-sized area in the buffer to handle pointers to pointers
     */
    uintptr_t *curr = (uintptr_t*) ret;
    while(curr < ((uintptr_t*)ret + size)) {
        *curr = (uintptr_t)curr + sizeof(uintptr_t);
        curr += sizeof(uintptr_t);
    }
    /* Make the last uintptr_t-sized area point to the beginning */
    *((uintptr_t*)ret + size - sizeof(uintptr_t)) = (uintptr_t)ret;
    buffers.insert(ret);
    return ret;
}
