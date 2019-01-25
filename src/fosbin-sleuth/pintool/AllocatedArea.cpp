//
// Created by derrick on 12/20/18.
//

ADDRINT AllocatedArea::MAGIC_VALUE = 0xA110CA3D;

AllocatedArea::AllocatedArea() :
        addr(0), malloc_addr(0) {
//    std::cout << "AllocatedArea default constructor" << std::endl;
    allocate_area(DEFAULT_ALLOCATION_SIZE);
    std::memset((void *) addr, 0, DEFAULT_ALLOCATION_SIZE);
}

AllocatedArea::AllocatedArea(const AllocatedArea &aa) :
        addr(0), malloc_addr(0) {
//    std::cout << "AllocatedArea copy constructor" << std::endl;
    allocate_area(aa.size());
    copy_allocated_area(aa);
}

AllocatedArea::~AllocatedArea() {
//    std::cout << "AllocatedArea destructor called. this = " << std::hex << (ADDRINT)this << std::endl;
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
            i += sizeof(AllocatedArea::MAGIC_VALUE) - 1;
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
//    std::cout << "AllocatedArea istream" << std::endl;
    for (AllocatedArea *subarea : ctx->subareas) {
        delete subarea;
    }

    uint64_t non_ptr_start = 0;
    uint64_t non_ptr_end = 0;
    size_t size;
    in.read((char *) &size, sizeof(size));
//    std::cout << "Allocated Area size = " << std::dec << size << " bytes" << std::endl;
    ctx->allocate_area(size);

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
                log_error("Invalid AllocatedArea input!");
            }
            AllocatedArea *aa = new AllocatedArea();
            ctx->subareas.push_back(aa);
//            std::cout << "Writing " << std::hex << (void*)aa->getAddr() << " to " << (void*)&c[i] << std::endl;
            i += sizeof(AllocatedArea::MAGIC_VALUE) - 1;
        } else {
            in.read(&c[i], sizeof(char));
//            std::cout << std::hex << ((int)c[i] & 0xff) << " ";
        }
    }
//    std::cout << std::endl;

    for (AllocatedArea *subarea : ctx->subareas) {
        in >> subarea;
    }

    c = (char *) ctx->malloc_addr;
    size_t subarea_cnt = 0;
    for (size_t i = 0; i < size; i++) {
        if (ctx->mem_map[i]) {
            ADDRINT *tmp = (ADDRINT * ) & c[i];
            AllocatedArea *aa = ctx->subareas[subarea_cnt++];
            *tmp = (ADDRINT) aa->getAddr();
            i += sizeof(AllocatedArea::MAGIC_VALUE) - 1;
        }
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
    std::stringstream ss;
    prettyPrint(ss, depth);
    log_message(ss);
}

void AllocatedArea::prettyPrint(std::ostream &s, size_t depth) const {
    s << std::hex << malloc_addr << ":" << std::endl;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if ((i % 16) == 0) {
            if (i > 0) { s << std::endl; }
            for (size_t j = 0; j < depth; j++) { s << "\t"; }
        }

        s << std::hex << std::setw(2) << std::setfill('0') << ((int) *((char *) malloc_addr + i) & 0xff) << " ";
    }

    s << std::endl;

    for (AllocatedArea *subarea : subareas) {
        subarea->prettyPrint(s, depth + 1);
    }
}

void AllocatedArea::copy_allocated_area(const AllocatedArea &orig) {
    mem_map = orig.mem_map;
    char *this_ptr = (char *) malloc_addr;
    char *that_ptr = (char *) orig.malloc_addr;
    size_t aa_num = 0;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (mem_map[i]) {
            AllocatedArea *aa = new AllocatedArea(*orig.get_subarea(aa_num++));
            subareas.push_back(aa);
            ADDRINT *tmp = (ADDRINT * ) & this_ptr[i];
//            std::cout << "copy_allocated_area setting " << std::hex << tmp << " to " << (void*)aa->getAddr() << std::endl;
            *tmp = (ADDRINT) aa->getAddr();
            i += sizeof(ADDRINT) - 1;
        } else {
//            std::cout << "Byte " << std::dec << i << " is getting set to " << std::hex << ((int)that_ptr[i] & 0xff) << std::endl;
            this_ptr[i] = that_ptr[i];
        }
    }
}

AllocatedArea &AllocatedArea::operator=(const AllocatedArea &orig) {
//    std::cout << "AllocatedArea copy" << std::endl;
    for (AllocatedArea *subarea : subareas) {
        delete subarea;
    }
    subareas.clear();
    allocate_area(orig.size());
    copy_allocated_area(orig);

    return *this;
}

void AllocatedArea::allocate_area(size_t size) {
    if (malloc_addr) {
        addr = (ADDRINT) realloc((void *) malloc_addr, size);
    } else {
        addr = (ADDRINT) malloc(size);
    }

    malloc_addr = addr;
    mem_map.resize(size);

//    std::cout << "Allocated " << std::dec << size << " bytes at " << std::hex << malloc_addr << std::endl;
}

bool AllocatedArea::operator!=(const AllocatedArea &other) const {
    return !(*this == other);
}

bool AllocatedArea::operator==(const AllocatedArea &other) const {
    std::stringstream ss;
    if (mem_map != other.mem_map) {
        ss << "Memory Maps are not the same" << std::endl;
        log_message(ss);
        return false;
    }

    const char *this_addr = (const char *) malloc_addr;
    const char *that_addr = (const char *) other.malloc_addr;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (!mem_map[i]) {
            if (this_addr[i] != that_addr[i]) {
                ss << "AllocatedArea bytes are not the same" << std::endl;
                ss << "This byte " << std::dec << i << " = " << std::hex << ((int) this_addr[i] & 0xff)
                          << std::endl;
                ss << "That byte " << std::dec << i << " = " << std::hex << ((int) that_addr[i] & 0xff)
                   << std::endl;
                log_message(ss);
                return false;
            }
        }
    }

    if (subareas.size() != other.subareas.size()) {
        ss << "subarea sizes are not the same";
        log_message(ss);
        return false;
    }

    for (size_t i = 0; i < subareas.size(); i++) {
        if (*subareas[i] != *other.get_subarea(i)) {
            ss << "Subareas are not the same" << std::endl;
            ss << "this size() = " << std::dec << subareas.size() << std::endl;
            ss << "that size() = " << std::dec << other.subareas.size() << std::endl;
            log_message(ss);
            return false;
        }
    }

    return true;
}

void AllocatedArea::reset_non_ptrs(const AllocatedArea &aa) {
    for (size_t i = 0; i < aa.size() && i < size(); i++) {
        if (!mem_map[i]) {
            ((char *) malloc_addr)[i] = ((char *) aa.getAddr())[i];
        }
    }

    for (size_t i = 0; i < subareas.size() && i < aa.subareas.size(); i++) {
        subareas[i]->reset_non_ptrs(*aa.subareas[i]);
    }
}

void AllocatedArea::setup_for_round(bool fuzz) {
//    std::cout << "Resetting 0x" << std::hex << addr << " to " << (fuzz ? "random" : "zero") << std::endl;
    for (AllocatedArea *subarea : subareas) {
        subarea->setup_for_round(fuzz);
    }

    int pointer_count = 0;
    uint8_t *curr = (uint8_t *) malloc_addr;
    for (size_t i = 0; i < mem_map.size(); i++) {
        size_t write_size;
        if (fuzz) {
            write_size = fuzz_strategy((uint8_t *) malloc_addr, size());
        } else {
            write_size = 1;
            *curr = '\0';
        }
//            std::cout << "Byte " << std::hex << (ADDRINT)curr << " set to " << ((int)*curr & 0xff) << std::endl;
        curr += write_size;
        i += write_size - 1;
    }
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (mem_map[i]) {
            AllocatedArea *aa = subareas[pointer_count];
//            std::cout << "Setting 0x" << (ADDRINT) curr << " to value 0x" << aa->getAddr() << std::endl;
            ADDRINT *ptr = (ADDRINT *) curr;
            *ptr = aa->getAddr();
            curr += sizeof(ADDRINT);
            i += sizeof(ADDRINT) - 1;
        }
    }
//    std::cout << "Done" << std::endl;
}

void AllocatedArea::fuzz() {
    setup_for_round(true);
}

bool AllocatedArea::fix_pointer(ADDRINT faulting_addr) {
    int64_t diff = faulting_addr - addr;
    std::stringstream ss;
//    std::cout << "Faulting addr: 0x" << std::hex << faulting_addr << " diff = 0x" << diff << std::endl;
    if (diff > (int64_t) size()) {
//        ss << "Diff (" << std::dec << diff << ") is outsize range (" << size() << ")" << std::endl;
//        log_message(ss);
        size_t subarea_idx = 0;
        for (AllocatedArea *subarea : subareas) {
            if (subarea->fix_pointer(faulting_addr)) {
//                ss << "Subarea " << std::dec << subarea_idx << " fixed" << std::endl;
//                log_message(ss);
                return true;
            }
            subarea_idx++;
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
        ADDRINT *addr_to_update = (ADDRINT * )((char *) malloc_addr + diff);
        *addr_to_update = aa->getAddr();
        subareas.push_back(aa);
//        std::cout << "Fixed pointer" << std::endl;
        return true;
    } else {
        ss << "Something weird happened. faulting_addr = 0x" << std::hex << faulting_addr << " and addr = 0x"
           << addr << std::endl;
        log_message(ss);
        return false;
    }
}
