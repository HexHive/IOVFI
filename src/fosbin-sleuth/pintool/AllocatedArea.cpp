//
// Created by derrick on 12/20/18.
//

ADDRINT AllocatedArea::MAGIC_VALUE = 0xA110CA3D;

AllocatedArea::AllocatedArea() {
    addr = (ADDRINT) malloc(DEFAULT_ALLOCATION_SIZE);
    malloc_addr = addr;
//    std::cout << "Allocated addr at 0x" << std::hex << addr << std::endl;
    std::memset((void *) addr, 0, DEFAULT_ALLOCATION_SIZE);
    mem_map.resize(DEFAULT_ALLOCATION_SIZE);
}

AllocatedArea::AllocatedArea(void *base) {
    size_t size;

    char *c = (char *) base;
    char *tmpaddr = (char *) malloc(DEFAULT_ALLOCATION_SIZE);

    for (size = 0; size < DEFAULT_ALLOCATION_SIZE && PIN_CheckReadAccess((void *) (c + size)); size++) {
        ADDRINT *tmp = (ADDRINT * ) & c[size];
        if (PIN_CheckReadAccess((void *) *tmp)) {
            mem_map[size] = true;
            void *subbase = (void *) *tmp;
            AllocatedArea * aa = new AllocatedArea(subbase);
            subareas.push_back(aa);
            *((ADDRINT * )(tmpaddr + size)) = (ADDRINT) aa;
            size += sizeof(void *);
        } else {
            mem_map[size] = false;
            tmpaddr[size] = c[size];
        }
    }

    addr = (ADDRINT) realloc((void *) tmpaddr, size);
    malloc_addr = addr;
}

AllocatedArea::~AllocatedArea() {
//    std::cout << "AllocatedArea destructor called" << std::endl;
//    std::cout << "Freeing 0x" << std::hex << malloc_addr << std::endl;
    free((void *) malloc_addr);
//    std::cout << "Freeing subareas" << std::endl;
    for (AllocatedArea *subarea : subareas) {
        delete subarea;
    }
//    std::cout << "AllocatedArea destructor finished" << std::endl;
}

ADDRINT AllocatedArea::getAddr() const {
    return malloc_addr;
}

size_t AllocatedArea::size() const {
    return mem_map.size();
}

std::ostream &operator<<(std::ostream &out, class AllocatedArea *ctx) {
    size_t size = ctx->size();
    out.write((const char *) &size, sizeof(size_t));

    std::copy(ctx->mem_map.begin(), ctx->mem_map.end(), std::ostreambuf_iterator<char>(out));

    char *c = (char *) ctx->malloc_addr;
    for (size_t i = 0; i < ctx->mem_map.size(); i++) {
        if (ctx->mem_map[i]) {
//            std::cout << std::hex << AllocatedArea::MAGIC_VALUE << " ";
            out.write((const char *) &AllocatedArea::MAGIC_VALUE, sizeof(AllocatedArea::MAGIC_VALUE));
            i += sizeof(AllocatedArea::MAGIC_VALUE);
        } else {
//            std::cout << std::setw(2) << ((int)c[i] & 0xff) << " ";
            out.write(&c[i], sizeof(char));
        }
    }

//    std::cout << std::endl;
    for (AllocatedArea *subarea : ctx->subareas) {
//        std::cout << "\t";
        out << subarea;
    }

    return out;
}

std::istream &operator>>(std::istream &in, class AllocatedArea *ctx) {
    for (AllocatedArea *subarea : ctx->subareas) {
        delete subarea;
    }

    uint64_t non_ptr_start = 0;
    uint64_t non_ptr_end = 0;
    size_t size;
    in.read((char *) &size, sizeof(size));
//    std::cout << "Allocated Area size = " << std::dec << size << " bytes" << std::endl;
    ctx->mem_map.resize(size);
    ctx->addr = (ADDRINT) std::realloc((void *) ctx->malloc_addr, size);
    ctx->malloc_addr = ctx->addr;

    for (size_t i = 0; i < size; i++) {
        char tmp;
        in.read((char *) &tmp, sizeof(tmp));
//        std::cout << std::hex << ((int)tmp & 0xff);
        ctx->mem_map[i] = (tmp != 0);
        if (tmp == 0) {
            non_ptr_end++;
        } else {
            if (non_ptr_start != non_ptr_end) {
//                std::cout << "Bytes " << std::dec << non_ptr_start << "-" << non_ptr_end - 1 << " are not pointers"
//                          << std::endl;
            }
            non_ptr_start = i;
            non_ptr_end = non_ptr_start;
        }
    }

//    std::cout << std::endl;
    char *c = (char *) ctx->malloc_addr;
    for (size_t i = 0; i < size; i++) {
        if (ctx->mem_map[i]) {
            ADDRINT magic;
            in.read((char *) &magic, sizeof(magic));
//            std::cout << std::hex << magic << " ";
            if (magic != AllocatedArea::MAGIC_VALUE) {
                std::cerr << "Invalid AllocatedArea input!" << std::endl;
                exit(1);
            }
            AllocatedArea *aa = new AllocatedArea();
            ctx->subareas.push_back(aa);
            ADDRINT *tmp = (ADDRINT * ) & c[i];
//            std::cout << "Writing " << std::hex << (void*)aa->getAddr() << " to " << (void*)&c[i] << std::endl;
            *tmp = (ADDRINT) aa->getAddr();
            i += sizeof(AllocatedArea::MAGIC_VALUE);
        } else {
            in.read(&c[i], sizeof(char));
//            std::cout << std::hex << ((int)c[i] & 0xff) << " ";
        }
    }
//    std::cout << std::endl;

    for (AllocatedArea *subarea : ctx->subareas) {
        in >> subarea;
    }

    return in;
}

AllocatedArea *AllocatedArea::get_subarea(size_t i) const {
    if (i >= subareas.size()) {
        return nullptr;
    }

    return subareas[i];
}

void AllocatedArea::prettyPrint(size_t depth) const {
    for (size_t i = 0; i < mem_map.size(); i++) {
        if ((i % 16) == 0) {
            if (i > 0) { std::cout << "\n"; }
            for (size_t j = 0; j < depth; j++) { std::cout << "\t"; }
        }

        std::cout << std::hex << ((int) *((char *) malloc_addr + i) & 0xff) << " ";
    }

    std::cout << std::endl;

    for (AllocatedArea *subarea : subareas) {
        subarea->prettyPrint(depth + 1);
    }
}

AllocatedArea &AllocatedArea::operator=(const AllocatedArea &orig) {
    for (AllocatedArea *subarea : subareas) {
        delete subarea;
    }
    subareas.clear();
    free((void *) malloc_addr);
    addr = (ADDRINT) malloc(orig.size());
    malloc_addr = addr;

    mem_map = orig.mem_map;
    char *this_ptr = (char *) malloc_addr;
    char *that_ptr = (char *) orig.malloc_addr;
    size_t aa_num = 0;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (mem_map[i]) {
            AllocatedArea *aa = new AllocatedArea();
            *aa = *orig.get_subarea(aa_num++);
            subareas.push_back(aa);
            ADDRINT *tmp = (ADDRINT * ) & this_ptr[i];
            *tmp = (ADDRINT) aa->getAddr();
            i += sizeof(void *);
        } else {
//            std::cout << "Byte " << std::dec << i << " is getting set to " << std::hex << ((int)that_ptr[i] & 0xff) << std::endl;
            this_ptr[i] = that_ptr[i];
        }
    }

    return *this;
}

bool AllocatedArea::operator!=(const AllocatedArea &other) const {
    return !(*this == other);
}

bool AllocatedArea::operator==(const AllocatedArea &other) const {
    if (mem_map != other.mem_map) {
        std::cout << "Memory Maps are not the same" << std::endl;
        return false;
    }

    const char *this_addr = (const char *) malloc_addr;
    const char *that_addr = (const char *) other.malloc_addr;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (!mem_map[i]) {
            if (this_addr[i] != that_addr[i]) {
                std::cout << "AllocatedArea bytes are not the same" << std::endl;
                std::cout << "This byte " << std::dec << i << " = " << std::hex << ((int) this_addr[i] & 0xff)
                          << std::endl;
                std::cout << "That byte " << std::dec << i << " = " << std::hex << ((int) that_addr[i] & 0xff)
                          << std::endl;
                return false;
            }
        }
    }

    if (subareas.size() != other.subareas.size()) {
        return false;
    }

    for (size_t i = 0; i < subareas.size(); i++) {
        if (*subareas[i] != *other.get_subarea(i)) {
            std::cout << "Subareas are not the same" << std::endl;
            std::cout << "this size() = " << std::dec << subareas.size() << std::endl;
            std::cout << "that size() = " << std::dec << other.subareas.size() << std::endl;
            return false;
        }
    }

    return true;
}

void AllocatedArea::reset() {
    setup_for_round(false);
}

void AllocatedArea::setup_for_round(bool fuzz) {
//    std::cout << "Resetting 0x" << std::hex << addr << " to " << (fuzz ? "random" : "zero") << std::endl;
    for (AllocatedArea *subarea : subareas) {
        subarea->setup_for_round(fuzz);
    }

    int pointer_count = 0;
    char *curr = (char *) addr;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (mem_map[i]) {
            AllocatedArea *aa = subareas[pointer_count];
//            std::cout << "Setting 0x" << (ADDRINT) curr << " to value 0x" << aa->getAddr() << std::endl;
            ADDRINT *ptr = (ADDRINT *) curr;
            *ptr = aa->getAddr();
            curr += sizeof(ADDRINT);
            i += sizeof(ADDRINT);
        } else {
            *curr = (fuzz ? rand() : 0);
            curr++;
        }
    }
//    std::cout << "Done" << std::endl;
}

void AllocatedArea::fuzz() {
    setup_for_round(true);
}

bool AllocatedArea::fix_pointer(ADDRINT faulting_addr) {
    int64_t diff = faulting_addr - addr;
//    std::cout << "Faulting addr: 0x" << std::hex << faulting_addr << " diff = 0x" << diff << std::endl;
    if (diff > (int64_t) size()) {
//        std::cout << "Diff (" << std::dec << diff << ") is outsize range (" << size() << ")" << std::endl;
        for (AllocatedArea *subarea : subareas) {
            if (subarea->fix_pointer(faulting_addr)) {
                return true;
            }
        }
        /* The expected size of this area is larger than expected
         * so time to resize
         */
        /* TODO: Implement resizing algorithm */
        return false;
    } else if (diff >= 0) {
//        std::cout << "Current submember" << std::endl;
        /* Some memory address inside this area is a pointer, so add a
         * new AllocatedArea to this one's subareas
         */
        AllocatedArea *aa = new AllocatedArea();
        for (size_t i = 0; i < sizeof(ADDRINT); i++) {
//            std::cout << "Byte " << std::dec << diff + i << " is marked a pointer" << std::endl;
            mem_map[diff + i] = true;
        }
        subareas.push_back(aa);
        return true;
    } else {
        std::cout << "Something weird happened. faulting_addr = 0x" << std::hex << faulting_addr << " and addr = 0x"
                  << addr << std::endl;
        return false;
    }
}