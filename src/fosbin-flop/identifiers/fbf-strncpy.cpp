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

    src_[sizeof(src_) / 2] = src_[0];
    std::memset(dst_, before, sizeof(dst_));
    func(dst_, src_, sizeof(dst_));
    FBF_ASSERT(std::strcmp(dst_, src_) == 0);

    src_[1] = '\0';
    std::memset(dst_, before, sizeof(dst_));
    func(dst_, src_, BYTES_COPIED);

    FBF_ASSERT(dst_[1] == '\0');
    FBF_ASSERT(dst_[0] == src_[0]);
    for(size_t i = 2; i < BYTES_COPIED; i++) {
        FBF_ASSERT(dst_[i] == before || dst_[i] == '\0');
    }

    return FunctionIdentifier::PASS;
}