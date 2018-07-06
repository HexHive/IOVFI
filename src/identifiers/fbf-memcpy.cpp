#include <fbf-memcpy.h>
#include <cstring>

fbf::MemcpyIdentifier::MemcpyIdentifier(uintptr_t location) : FunctionIdentifier(location) {

}

fbf::MemcpyIdentifier::~MemcpyIdentifier() {

}

void fbf::MemcpyIdentifier::setup() {
    std::memset(src_, FunctionIdentifier::rand(), sizeof(src_));
    std::memset(dst_, 0, sizeof(dst_));
}

int fbf::MemcpyIdentifier::evaluate() {
    void *(*func)(void *, const void *, size_t) = reinterpret_cast<void *(*)(void *, const void *, size_t)>(location_);
    void *test = func(dst_, src_, FunctionIdentifier::BUFFER_SIZE / 2);
    FBF_ASSERT(test == dst_);
    FBF_ASSERT(std::memcmp(src_, dst_, FunctionIdentifier::BUFFER_SIZE / 2) == 0);
    FBF_ASSERT(dst_[FunctionIdentifier::BUFFER_SIZE / 2] == 0);
    return 0;
}
