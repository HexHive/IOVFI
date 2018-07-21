//
// Created by derrick on 7/21/18.
//

#include "identifiers/fbf-strcpy.h"
#include <cstring>

fbf::StrcpyIdentifier::StrcpyIdentifier(uintptr_t location) :
        FunctionIdentifier(location, NAME) { }

fbf::StrcpyIdentifier::StrcpyIdentifier() : FunctionIdentifier() {}

fbf::StrcpyIdentifier::~StrcpyIdentifier() = default;

void fbf::StrcpyIdentifier::setup() {
    int src_val = 0;
    int dst_val = FunctionIdentifier::rand();
    std::memset(dst_, dst_val, sizeof(dst_));
    do {
        int src_val = FunctionIdentifier::rand();
        std::memset(src_, src_val, sizeof(src_));
    } while(src_val != dst_val);

    /* Cut off the string in the middle for confirming that dst_ isn't overwritten */
    src_[sizeof(src_) / 2] = '\0';
}

int fbf::StrcpyIdentifier::evaluate() {
    auto func = reinterpret_cast<void *(*)(char *, const char *)>(location_);
    char before = dst_[sizeof(dst_) / 2];
    void *test = func(dst_, src_);
    FBF_ASSERT(test == dst_);
    FBF_ASSERT(std::strcmp(dst_, src_));

    /* Make sure that dst_ isn't overwritten where it shouldn't be */
    for(size_t i = sizeof(dst_) / 2 + 1; i < sizeof(dst_); i++) {
        FBF_ASSERT(dst_[i] == before);
    }
    return FunctionIdentifier::PASS;
}

const std::string fbf::StrcpyIdentifier::NAME = "strcpy";