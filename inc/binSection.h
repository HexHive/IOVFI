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
        BinSection(uintptr_t location, size_t size);
        BinSection();
        uintptr_t location_;
        size_t size_;
    };
}


#endif //FOSBIN_FLOP_BINSECTION_H
