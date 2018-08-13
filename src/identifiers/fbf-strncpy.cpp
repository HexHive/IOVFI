//
// Created by derrick on 8/13/18.
//

#include "identifiers/fbf-strncpy.h"
#include <cstring>

fbf::StrncpyIdentifier::StrncpyIdentifier(uintptr_t location) :
        StrcpyIdentifier(location, "strncpy") {}

fbf::StrncpyIdentifier::StrncpyIdentifier() : StrcpyIdentifier() {}

const size_t fbf::StrncpyIdentifier::BYTES_COPIED = fbf::FunctionIdentifier::BUFFER_SIZE / 4;

int fbf::StrncpyIdentifier::evaluate() {
    auto func = reinterpret_cast<char *(*)(char *, const char *, size_t)>(location_);
    char before = dst_[sizeof(dst_) / 2];
    char *test = func(dst_, src_, BYTES_COPIED);
    FBF_ASSERT(test == dst_);
    FBF_ASSERT(std::strncmp(dst_, src_, BYTES_COPIED) == 0);

    /* Make sure that dst_ isn't overwritten where it shouldn't be */
    for(size_t i = BYTES_COPIED + 1; i < sizeof(dst_); i++) {
        FBF_ASSERT(dst_[i] == before);
    }
    return FunctionIdentifier::PASS;
}