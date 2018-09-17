//
// Created by derrick on 7/21/18.
//

#include <identifiers/fbf-sprintf.h>
#include <cstring>

#include "identifiers/fbf-sprintf.h"

fbf::SprintfIdentifier::SprintfIdentifier(uintptr_t location) :
                            FunctionIdentifier(location, "sprintf") { }

fbf::SprintfIdentifier::SprintfIdentifier()  : FunctionIdentifier() {}

fbf::SprintfIdentifier::~SprintfIdentifier() = default;

int fbf::SprintfIdentifier::evaluate() {
    auto func = reinterpret_cast<int (*)(char*, const char*, ...)>(location_);
    int rand1 = FunctionIdentifier::rand();
    int rand2 = FunctionIdentifier::rand();

    int test2 = std::sprintf(dst2_, format_, rand1, rand2);
    int test1 = func(dst1_, format_, rand1, rand2);

    FBF_ASSERT(test1 == test2);
    FBF_ASSERT(std::strcmp(dst1_, dst2_) == 0);
    return ITestCase::PASS;
}

void fbf::SprintfIdentifier::setup() {
    std::memset(dst1_, 0, sizeof(dst1_));
    std::memset(dst2_, 0, sizeof(dst2_));
}
