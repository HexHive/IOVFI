//
// Created by derrick on 12/20/18.
//

ADDRINT AllocatedArea::MAGIC_VALUE = 0xA110CA3D;

AllocatedArea::AllocatedArea() {
    addr = (ADDRINT) malloc(DEFAULT_ALLOCATION_SIZE);
    std::memset((void *) addr, 0, DEFAULT_ALLOCATION_SIZE);
    mem_map.resize(DEFAULT_ALLOCATION_SIZE);
}

AllocatedArea::~AllocatedArea() {
    for (AllocatedArea *subarea : subareas) {
        delete subarea;
    }
    free((void *) addr);
}

ADDRINT AllocatedArea::getAddr() {
    return addr;
}

size_t AllocatedArea::size() {
    return mem_map.size();
}

std::ostream &operator<<(std::ostream &out, class AllocatedArea *ctx) {
    size_t size = ctx->size();
    out.write((const char *) &size, sizeof(size_t));

    std::copy(ctx->mem_map.begin(), ctx->mem_map.end(), std::ostreambuf_iterator<char>(out));

    char *c = (char *) ctx->addr;
    for (size_t i = 0; i < ctx->mem_map.size(); i++) {
        if (ctx->mem_map[i]) {
            out.write((const char *) &AllocatedArea::MAGIC_VALUE, sizeof(AllocatedArea::MAGIC_VALUE));
            i += sizeof(AllocatedArea::MAGIC_VALUE);
        } else {
            out.write(&c[i], sizeof(char));
        }
    }

    for (AllocatedArea *subarea : ctx->subareas) {
        out << subarea;
    }

    return out;
}

void AllocatedArea::reset() {
    setup_for_round(false);
}

void AllocatedArea::setup_for_round(bool fuzz) {
    for (AllocatedArea *subarea : subareas) {
        subarea->setup_for_round(fuzz);
    }

    int pointer_count = 0;
    char *curr = (char *) addr;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (mem_map[i]) {
            ADDRINT *ptr = (ADDRINT *) curr;
            *ptr = subareas[pointer_count++]->addr;
            curr += sizeof(ADDRINT);
        } else {
            *curr = (fuzz ? rand() : 0);
            curr++;
        }
    }
}

void AllocatedArea::fuzz() {
    setup_for_round(true);
}

bool AllocatedArea::fix_pointer(ADDRINT faulting_addr) {
    int64_t diff = faulting_addr - addr;
    if (diff > (int64_t) size()) {
        std::cout << "Diff (" << std::dec << diff << ") is outsize range (" << size() << ")" << std::endl;
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
        /* Some memory address inside this area is a pointer, so add a
         * new AllocatedArea to this one's subareas
         */
        AllocatedArea *aa = new AllocatedArea();
        for (size_t i = 0; i < sizeof(ADDRINT); i++) {
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