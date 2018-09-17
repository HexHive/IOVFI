#include <identifiers/fbf-memcpy.h>
#include <cstring>

fbf::MemcpyIdentifier::MemcpyIdentifier(uintptr_t location) :
                                FunctionIdentifier(location, "memcpy") { }

fbf::MemcpyIdentifier::MemcpyIdentifier() : FunctionIdentifier() {}

fbf::MemcpyIdentifier::~MemcpyIdentifier() = default;

void fbf::MemcpyIdentifier::setup() {
    std::memset(src_, FunctionIdentifier::rand(), sizeof(src_));
    std::memset(dst_, 0, sizeof(dst_));
    /* Exclude the possibility of string copying related false positives */
    src_[1] = '\0';
}

int fbf::MemcpyIdentifier::evaluate() {
    auto func = reinterpret_cast<void *(*)(void *, const void *, size_t)>(location_);
    void *test = func(dst_, src_, FunctionIdentifier::BUFFER_SIZE / 2);

    char zero[FunctionIdentifier::BUFFER_SIZE / 2];
    std::memset(zero, 0, sizeof(zero));
    FBF_ASSERT(test == dst_);
    FBF_ASSERT(std::memcmp(src_, dst_, FunctionIdentifier::BUFFER_SIZE / 2) == 0);
    FBF_ASSERT(std::memcmp(dst_ + FunctionIdentifier::BUFFER_SIZE / 2, zero, sizeof(zero)) == 0);

    return ITestCase::PASS;
}
