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
    for(size_t i = 0; i < MAX_ARGUMENTS; i++) {
        create_buffer(ITestCase::POINTER_SIZE);
    }

    make_fuzzer<void, double, void*, void*>(0.0, buffers[0], buffers[1]);

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
    LOG_DEBUG << "Allocated buffer at 0x" << std::hex << ret;

    /* Make each uintptr_t-sized area point to the immediate next
     * uintptr_t-sized area in the buffer to handle pointers to pointers
     */
    uintptr_t *curr = (uintptr_t*) ret;
    while(curr < (uintptr_t*)((uintptr_t)ret + size)) {
        *curr = (uintptr_t)((uintptr_t)curr + sizeof(uintptr_t));
        curr += sizeof(uintptr_t);
    }
    /* Make the last uintptr_t-sized area point to the beginning */
    *((uintptr_t*)ret + size - sizeof(uintptr_t)) = (uintptr_t)ret;
    buffers.push_back(ret);
    return ret;
}

template<typename R, typename... Args>
std::shared_ptr<fbf::FosbinFuzzer<R, Args...>> fbf::FullFuzzTest::make_fuzzer(Args... args) {
    std::shared_ptr<fbf::FosbinFuzzer<R, Args...>> tmp =
            std::make_shared<fbf::FosbinFuzzer<R, Args...>>(binDesc_, std::make_tuple(args...));

    fuzzers[sizeof...(Args)].push_back(tmp);
    return tmp;
}
