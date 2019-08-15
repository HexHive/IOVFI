//
// Created by derrick on 12/20/18.
//

ADDRINT AllocatedArea::MAGIC_VALUE = 0xA110CA3D;

AllocatedArea::AllocatedArea() :
        malloc_addr(0), lower_guard(0), upper_guard(0) {
    allocate_area(DEFAULT_ALLOCATION_SIZE);
    std::memset((void *) malloc_addr, 0, DEFAULT_ALLOCATION_SIZE);
}

AllocatedArea::AllocatedArea(const AllocatedArea &aa) :
        malloc_addr(0), lower_guard(0), upper_guard(0) {
    allocate_area(aa.size());
    copy_allocated_area(aa);
}

AllocatedArea::~AllocatedArea() {
    munmap(malloc_addr, getpagesize());
    for (AllocatedArea *subarea : subareas) {
        delete subarea;
    }
}

ADDRINT AllocatedArea::getAddr() const {
    return (ADDRINT) malloc_addr;
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
            out.write((const char *) &AllocatedArea::MAGIC_VALUE, sizeof(AllocatedArea::MAGIC_VALUE));
            i += sizeof(AllocatedArea::MAGIC_VALUE) - 1;
        } else {
            out.write(&c[i], sizeof(char));
        }
    }

    for (AllocatedArea *subarea : ctx->subareas) {
        out << subarea;
    }

    return out;
}

std::istream &operator>>(std::istream &in, class AllocatedArea *ctx) {
    for (AllocatedArea *subarea : ctx->subareas) {
        delete subarea;
    }

    ctx->subareas.clear();

    uint64_t non_ptr_start = 0;
    uint64_t non_ptr_end = 0;
    size_t size;
    in.read((char *) &size, sizeof(size));
    ctx->allocate_area(size);

    for (size_t i = 0; i < size; i++) {
        char tmp;
        in.read((char *) &tmp, sizeof(tmp));
        ctx->mem_map[i] = (tmp != 0);
        if (tmp == 0) {
            non_ptr_end++;
        } else {
            if (non_ptr_start != non_ptr_end) {
            }
            non_ptr_start = i;
            non_ptr_end = non_ptr_start;
        }
    }

    char *c = (char *) ctx->malloc_addr;
    for (size_t i = 0; i < size; i++) {
        if (ctx->mem_map[i]) {
            ADDRINT magic;
            in.read((char *) &magic, sizeof(magic));
            if (magic != AllocatedArea::MAGIC_VALUE) {
                log_error("Invalid AllocatedArea input!");
            }
            AllocatedArea *aa = new AllocatedArea();
            ctx->subareas.push_back(aa);
            i += sizeof(AllocatedArea::MAGIC_VALUE) - 1;
        } else {
            in.read(&c[i], sizeof(char));
        }
    }

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
    s << std::hex << getAddr() << ":" << std::endl;
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
            *tmp = (ADDRINT) aa->getAddr();
            i += sizeof(ADDRINT) - 1;
        } else {
            this_ptr[i] = that_ptr[i];
        }
    }
}

AllocatedArea &AllocatedArea::operator=(const AllocatedArea &orig) {
    for (AllocatedArea *subarea : subareas) {
        delete subarea;
    }
    subareas.clear();
    allocate_area(orig.size());
    copy_allocated_area(orig);

    return *this;
}

void AllocatedArea::unmap_guard_pages() {
    if (lower_guard > 0) {
        munmap((void *) lower_guard, getpagesize());
    }

    if (upper_guard > 0) {
        munmap((void *) upper_guard, getpagesize());
    }
}

void AllocatedArea::allocate_area(size_t size) {
    std::stringstream msg;
    if (malloc_addr) {
        unmap_guard_pages();
        munmap((void *) malloc_addr, getpagesize());
    }

    if (size > (size_t) getpagesize()) {
        /* Too boku */
        size = getpagesize();
    }

    lower_guard = (char *) mmap(nullptr, getpagesize(), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (lower_guard < 0) {
        msg << "lower_guard: " << strerror(errno);
        log_message(msg);
        goto error;
    }
    malloc_addr = (char *) mmap(lower_guard + getpagesize(), getpagesize(), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (malloc_addr < 0) {
        msg << "malloc_addr: " << strerror(errno);
        log_message(msg);
        goto error;
    }
    upper_guard = (char *) mmap(malloc_addr + getpagesize(), getpagesize(), PROT_NONE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (upper_guard < 0) {
        msg << "upper_guard: " << strerror(errno);
        log_message(msg);
        goto error;
    }

//    msg << "lower_guard: " << std::hex << lower_guard
//        << "malloc_addr: " << std::hex << malloc_addr
//        << "upper_guard: " << std::hex << upper_guard;
//    log_message(msg);
    mem_map.resize(size);
    return;

    error:
    unmap_guard_pages();
    log_error("Could not memory map allocated area");
}

bool AllocatedArea::operator!=(const AllocatedArea &other) const {
    return !(*this == other);
}

bool AllocatedArea::operator==(const AllocatedArea &other) const {
    std::stringstream ss;
    if (mem_map != other.mem_map) {
//        ss << "Memory Maps are not the same" << std::endl;
//        log_message(ss);
        return false;
    }

    const char *this_addr = (const char *) malloc_addr;
    const char *that_addr = (const char *) other.malloc_addr;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (!mem_map[i]) {
            if (this_addr[i] != that_addr[i]) {
//                ss << "AllocatedArea bytes are not the same" << std::endl;
//                ss << "This byte " << std::dec << i << " = " << std::hex << ((int) this_addr[i] & 0xff)
//                          << std::endl;
//                ss << "That byte " << std::dec << i << " = " << std::hex << ((int) that_addr[i] & 0xff)
//                   << std::endl;
//                log_message(ss);
                return false;
            }
        }
    }

    if (subareas.size() != other.subareas.size()) {
//        ss << "subarea sizes are not the same";
//        log_message(ss);
        return false;
    }

    for (size_t i = 0; i < subareas.size(); i++) {
        if (*subareas[i] != *other.get_subarea(i)) {
//            ss << "Subareas are not the same" << std::endl;
//            ss << "this size() = " << std::dec << subareas.size() << std::endl;
//            ss << "that size() = " << std::dec << other.subareas.size() << std::endl;
//            log_message(ss);
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
        curr += write_size;
        i += write_size - 1;
    }
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (mem_map[i]) {
            AllocatedArea *aa = subareas[pointer_count];
            ADDRINT *ptr = (ADDRINT *) curr;
            *ptr = aa->getAddr();
            curr += sizeof(ADDRINT);
            i += sizeof(ADDRINT) - 1;
        }
    }
}

void AllocatedArea::fuzz() {
    setup_for_round(true);
}

bool AllocatedArea::fix_pointer(ADDRINT faulting_addr) {
    int64_t diff = faulting_addr - (ADDRINT) malloc_addr;
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
        /* Some memory address inside this area is a pointer, so add a
         * new AllocatedArea to this one's subareas
         */
        AllocatedArea *aa = new AllocatedArea();
        for (size_t i = 0; i < sizeof(ADDRINT); i++) {
            mem_map[diff + i] = true;
        }
        ADDRINT *addr_to_update = (ADDRINT * )((char *) malloc_addr + diff);
        *addr_to_update = aa->getAddr();
        subareas.push_back(aa);
        return true;
    } else {
        ss << "Something weird happened. faulting_addr = 0x" << std::hex << faulting_addr << " and addr = 0x"
           << malloc_addr << std::endl;
        log_message(ss);
        return false;
    }
}
