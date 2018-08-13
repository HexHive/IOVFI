//
// Created by derrick on 8/13/18.
//

#include "identifiers/fbf-memmove.h"
#include <cstring>

fbf::MemmoveIdentifier::MemmoveIdentifier(uintptr_t location) :
    FunctionIdentifier(location, "memmove") {}

fbf::MemmoveIdentifier::MemmoveIdentifier() : FunctionIdentifier() {}

fbf::MemmoveIdentifier::~MemmoveIdentifier() = default;

const int fbf::MemmoveIdentifier::OFFSET = 2;

/**
 * @brief Tests to see if location_ is memmove
 * @return true if location_ is memmove
 *
 * Memmove behaves as if src data is copied to another buffer first, before
 * the move happens.  Thus it can accept overlapping pointers as input, and
 * the original data should be written to dest regardless of what is there after
 * the write starts.
 */
int fbf::MemmoveIdentifier::evaluate() {
    auto func = reinterpret_cast<void *(*)(void *, const void *, size_t)>(location_);

    char orig[FunctionIdentifier::BUFFER_SIZE - OFFSET];
    std::memcpy(orig, src_, sizeof(orig));

    void* test = func(src_ + OFFSET, src_, sizeof(src_) - OFFSET);
    FBF_ASSERT(test == src_ + OFFSET);
    FBF_ASSERT(std::memcmp(src_ + OFFSET, orig, sizeof(orig)));

    return FunctionIdentifier::PASS;
}

void fbf::MemmoveIdentifier::setup() {
    /* Make every value in the buffer to be different,
     * so that we can distinguish between memcpy and
     * memmove
     */
    for(size_t i = 0; i < sizeof(src_); i++) {
        src_[i] = (char)FunctionIdentifier::rand();
    }
}
