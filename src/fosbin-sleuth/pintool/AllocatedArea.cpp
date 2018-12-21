//
// Created by derrick on 12/20/18.
//

ADDRINT AllocatedArea::MAGIC_VALUE = 0xA110CA3D;

AllocatedArea::AllocatedArea() {
    addr = (ADDRINT) malloc(DEFAULT_ALLOCATION_SIZE);
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
    out << ctx->size();

    for (size_t i = 0; i < ctx->mem_map.size(); i++) {
        out << ctx->mem_map[i];
    }

    char *c = (char *) ctx->addr;
    for (size_t i = 0; i < ctx->mem_map.size(); i++) {
        if (ctx->mem_map[i]) {
            out << AllocatedArea::MAGIC_VALUE;
            i += sizeof(AllocatedArea::MAGIC_VALUE);
        } else {
            out << c[i];
        }
    }

    for (AllocatedArea *subarea : ctx->subareas) {
        out << subarea;
    }

    return out;
}

void AllocatedArea::reset() {
    for (AllocatedArea *subarea : subareas) {
        subarea->reset();
    }

    int pointer_count = 0;
    char *curr = (char *) addr;
    for (size_t i = 0; i < mem_map.size(); i++) {
        if (mem_map[i]) {
            ADDRINT *ptr = (ADDRINT *) curr;
            *ptr = subareas[pointer_count++]->addr;
            curr += sizeof(ADDRINT);
        } else {
            *curr = 0;
            curr++;
        }
    }
}