//
// Created by derrick on 9/20/18.
//

#include <fosbin-sleuth/protectedBuffer.h>

#include "fosbin-sleuth/protectedBuffer.h"

#include <sys/mman.h>
#include <stdexcept>

fbf::ProtectedBuffer::ProtectedBuffer(size_t bufsize, size_t guardsize) :
        buffer(nullptr, 0), guards(2) {
    uint8_t *ptr = (uint8_t *) mmap(NULL, guardsize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        throw std::runtime_error("Could not allocate guard page");
    }
    std::shared_ptr<uint8_t> sp1(ptr, [guardsize](uint8_t *ptr) { munmap(ptr, guardsize); });
    guards[0].first = sp1;
    guards[0].second = guardsize;

    uint8_t *buf = (uint8_t *) mmap(ptr + guards[0].second,
                                    bufsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        munmap(guards[0].first.get(), guards[0].second);
        throw std::runtime_error("Could not allocate guard page");
    }
    std::shared_ptr<uint8_t> sp2(buf, [bufsize](uint8_t *ptr) { munmap(ptr, bufsize); });
    buffer.first = sp2;
    buffer.second = bufsize;

    ptr = (uint8_t *) mmap(buf + buffer.second, guardsize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        munmap(guards[0].first.get(), guards[0].second);
        munmap(buffer.first.get(), buffer.second);
        throw std::runtime_error("Could not allocate guard page");
    }
    std::shared_ptr<uint8_t> sp3(ptr, [guardsize](uint8_t *ptr) { munmap(ptr, guardsize); });
    guards[1].first = sp3;
    guards[1].second = guardsize;
}

fbf::ProtectedBuffer::~ProtectedBuffer() {
/*    for(std::pair<std::shared_ptr<uint8_t>, size_t> guard : guards) {
        if(guard.first.use_count() <= 1) {
            munmap(guard.first.get(), guard.second);
        }
    }

    if(buffer.first.use_count() <= 1) {
        munmap(buffer.first.get(), buffer.second);
    }*/
}

uint8_t &fbf::ProtectedBuffer::operator[](size_t i) {
    return buffer.first.get()[i];
}

uint8_t fbf::ProtectedBuffer::operator[](size_t i) const {
    return buffer.first.get()[i];
}

uint8_t *fbf::ProtectedBuffer::operator&() {
    return buffer.first.get();
}

fbf::ProtectedBuffer::ProtectedBuffer(const fbf::ProtectedBuffer &orig)
        : guards(orig.guards), buffer(orig.buffer) {}

fbf::ProtectedBuffer &fbf::ProtectedBuffer::operator=(const fbf::ProtectedBuffer &other) {
    if (this != &other) {
        guards = other.guards;
        buffer = other.buffer;
    }

    return *this;
}
