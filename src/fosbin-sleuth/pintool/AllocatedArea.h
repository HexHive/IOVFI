//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_ALLOCATEDAREA_H
#define FOSBIN_ALLOCATEDAREA_H

#include "pin.H"
#include <vector>
#include <iostream>

#define DEFAULT_ALLOCATION_SIZE 4096

class AllocatedArea {
public:
    AllocatedArea();

    AllocatedArea(const AllocatedArea &aa);

    ~AllocatedArea();

    ADDRINT getAddr() const;

    size_t size() const;

    void reset_non_ptrs(const AllocatedArea &aa);

    void fuzz();

    bool fix_pointer(ADDRINT faulting_addr);

    /* Used to indicate if a memory area is another AllocatedArea */
    static ADDRINT MAGIC_VALUE;

    friend std::ostream &operator<<(std::ostream &out, class AllocatedArea *ctx);

    friend std::istream &operator>>(std::istream &in, class AllocatedArea *ctx);

    AllocatedArea &operator=(const AllocatedArea &orig);

    bool operator==(const AllocatedArea &other) const;

    bool operator!=(const AllocatedArea &other) const;

    AllocatedArea *get_subarea(size_t i) const;

    void prettyPrint(size_t depth) const;

    void prettyPrint(std::ostream &o, size_t depth) const;

protected:
    char *malloc_addr, *lower_guard, *upper_guard;
    std::vector<bool> mem_map;
    std::vector<AllocatedArea *> subareas;

    void copy_allocated_area(const AllocatedArea &orig);

    void allocate_area(size_t size);

    void unmap_guard_pages();

    void setup_for_round(bool fuzz);
};

#endif //FOSBIN_ALLOCATEDAREA_H
