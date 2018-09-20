//
// Created by derrick on 9/20/18.
//

#ifndef FOSBIN_PROTECTEDBUFFER_H
#define FOSBIN_PROTECTEDBUFFER_H

#include <cstddef>
#include <utility>
#include <vector>

namespace fbf {
#define PAGE_SIZE   4096
    class ProtectedBuffer {
    public:
        ProtectedBuffer(size_t bufsize, size_t guardsize = PAGE_SIZE);
        ~ProtectedBuffer();

        unsigned char operator[](size_t i) const;
        unsigned char& operator[](size_t i);

        void* operator&();

    protected:
        std::vector<std::pair<void*, size_t>> guards;
        std::pair<void*, size_t> buffer;
    };
}

#endif //FOSBIN_PROTECTEDBUFFER_H
