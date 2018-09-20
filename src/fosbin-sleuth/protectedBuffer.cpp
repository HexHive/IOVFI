//
// Created by derrick on 9/20/18.
//

#include <fosbin-sleuth/protectedBuffer.h>

#include "fosbin-sleuth/protectedBuffer.h"

#include <sys/mman.h>
#include <stdexcept>

fbf::ProtectedBuffer::ProtectedBuffer(size_t bufsize, size_t guardsize) :
    buffer(0, 0), guards(2)
{
    void* ptr = mmap(NULL, guardsize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(ptr == MAP_FAILED) {
        throw std::runtime_error("Could not allocate guard page");
    }
    guards[0].first = ptr;
    guards[0].second = guardsize;

    ptr = mmap((char*)ptr + guardsize, bufsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(ptr == MAP_FAILED) {
        munmap(guards[0].first, guards[0].second);
        throw std::runtime_error("Could not allocate guard page");
    }
    buffer.first = ptr;
    buffer.second = bufsize;

    ptr = mmap((char*)buffer.first + bufsize, guardsize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(ptr == MAP_FAILED) {
        munmap(guards[0].first, guards[0].second);
        munmap(buffer.first, buffer.second);
        throw std::runtime_error("Could not allocate guard page");
    }
    guards[1].first = ptr;
    guards[1].second = guardsize;
}

fbf::ProtectedBuffer::~ProtectedBuffer() {
    for(std::pair<void*, size_t> guard : guards) {
        munmap(guard.first, guard.second);
    }

    if(buffer.first) {
        munmap(buffer.first, buffer.second);
    }
}

unsigned char &fbf::ProtectedBuffer::operator[](size_t i) {
    return ((unsigned char*)buffer.first)[i];
}

unsigned char fbf::ProtectedBuffer::operator[](size_t i) const {
    return ((unsigned char*)buffer.first)[i];
}

void *fbf::ProtectedBuffer::operator&() {
    return buffer.first;
}
