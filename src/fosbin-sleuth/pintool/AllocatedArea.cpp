//
// Created by derrick on 12/20/18.
//

AllocatedArea::AllocatedArea() {
    addr = (ADDRINT) malloc(DEFAULT_ALLOCATION_SIZE);
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