//
// Created by derrick on 7/21/18.
//

#include "identifiers/fbf-strcpy.h"
#include <cstring>
#include <identifiers/fbf-strcpy.h>


fbf::StrcpyIdentifier::StrcpyIdentifier(uintptr_t location) :
        FunctionIdentifier(location, "strcpy") { }

fbf::StrcpyIdentifier::StrcpyIdentifier() : FunctionIdentifier() {}

fbf::StrcpyIdentifier::~StrcpyIdentifier() = default;

fbf::StrcpyIdentifier::StrcpyIdentifier(uintptr_t location, const std::string &subclass_name) :
        FunctionIdentifier(location, subclass_name) { }

void fbf::StrcpyIdentifier::setup() {
    int src_val = 0;
    int dst_val = FunctionIdentifier::rand();
    std::memset(dst_, dst_val, sizeof(dst_));
    /* Make sure that src and dst are not the same */
    do {
        src_val = FunctionIdentifier::rand();
        std::memset(src_, src_val, sizeof(src_));
    } while(src_val == dst_val);

    /* Cut off the string in the middle for confirming that dst_ isn't overwritten */
    src_[sizeof(src_) / 2] = '\0';
    src_[sizeof(src_) - 1] = '\0';
}

int fbf::StrcpyIdentifier::evaluate() {
    /* Make variadic to test that location_ is NOT strncpy */
    auto func = reinterpret_cast<char *(*)(char *, const char *, size_t)>(location_);
    char before = dst_[sizeof(dst_) / 2];
    char *test = func(dst_, src_, 0);
    FBF_MAJOR_ASSERT(test == dst_);
    FBF_MAJOR_ASSERT(std::strcmp(dst_, src_) == 0);

    /* Make sure that dst_ isn't overwritten where it shouldn't be */
    for(size_t i = sizeof(dst_) / 2 + 1; i < sizeof(dst_); i++) {
        FBF_ASSERT(dst_[i] == before);
    }

    return ITestCase::PASS;
}