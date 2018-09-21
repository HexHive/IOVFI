//
// Created by derrick on 9/20/18.
//

#ifndef FOSBIN_PROTECTEDBUFFER_H
#define FOSBIN_PROTECTEDBUFFER_H

#include <cstddef>
#include <utility>
#include <vector>
#include <memory>

namespace fbf {
#define PAGE_SIZE   4096

    class ProtectedBuffer {
    public:
        ProtectedBuffer(size_t bufsize, size_t guardsize = PAGE_SIZE);

        ProtectedBuffer(const ProtectedBuffer &orig);

        ~ProtectedBuffer();

        uint8_t operator[](size_t i) const;

        uint8_t &operator[](size_t i);

        ProtectedBuffer &operator=(const ProtectedBuffer &other);

        uint8_t *operator&();

    protected:
        std::vector<std::pair<std::shared_ptr<uint8_t>, size_t> > guards;
        std::pair<std::shared_ptr<uint8_t>, size_t> buffer;
    };
}

#endif //FOSBIN_PROTECTEDBUFFER_H
