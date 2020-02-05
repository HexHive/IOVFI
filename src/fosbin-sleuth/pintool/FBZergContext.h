//
// Created by derrick on 2/4/20.
//

#ifndef FOSBIN_FBZERGCONTEXT_H
#define FOSBIN_FBZERGCONTEXT_H

#include "pin.H"
#include <iostream>
#include <set>
#include <vector>
#include "AllocatedArea.h"
#include "FBZergContext.h"

class FBZergContext {
public:
    FBZergContext();

    ~FBZergContext();

    friend std::ostream &operator<<(std::ostream &out, const FBZergContext &ctx);

    friend std::istream &operator>>(std::istream &in, FBZergContext &ctx);

    CONTEXT *operator>>(CONTEXT *ctx) const;

    FBZergContext &operator<<(CONTEXT *ctx);

    FBZergContext &operator=(const FBZergContext &orig);

    bool operator==(const FBZergContext &ctx) const;

    bool operator!=(const FBZergContext &ctx) const;

    void add(REG reg, AllocatedArea *aa);

    void add(REG reg, ADDRINT value);

    AllocatedArea *find_allocated_area(REG reg) const;

    const static REG argument_regs[];

    const static size_t argument_count;

    const static REG return_reg;

    ADDRINT get_value(REG reg) const;

    void prettyPrint() const;

    void prettyPrint(std::ostream &s) const;

    void reset_non_ptrs(const FBZergContext &ctx);

    bool return_is_ptr() const;

protected:
    std::map <REG, ADDRINT> values;
    std::map<REG, AllocatedArea *> pointer_registers;
    char return_value;

private:
    bool return_values_equal(const FBZergContext &ctx) const;

    int64_t sign_extend(int64_t orig) const;
};

#endif //FOSBIN_FBZERGCONTEXT_H
