//
// Created by derrick on 8/17/18.
//

#include <binSection.h>

fbf::BinSection::BinSection(uintptr_t location, uintptr_t offset, size_t size) :
    location_(location), offset_(offset), size_(size) { }

fbf::BinSection::BinSection() : location_(0), size_(0), offset_(0) { }
