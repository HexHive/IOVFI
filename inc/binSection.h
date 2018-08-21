//
// Created by derrick on 8/17/18.
//

#ifndef FOSBIN_FLOP_BINSECTION_H
#define FOSBIN_FLOP_BINSECTION_H

#include <cstddef>
#include <cstdint>

namespace fbf {
    class BinSection {
    public:
        BinSection(uintptr_t location, uintptr_t offset, size_t size);
        BinSection();
        uintptr_t offset_;
        size_t size_;
        uintptr_t location_;
    };
}


#endif //FOSBIN_FLOP_BINSECTION_H
