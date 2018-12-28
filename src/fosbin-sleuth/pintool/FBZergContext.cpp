//
// Created by derrick on 12/27/18.
//

#include "pin.H"

const REG FBZergContext::argument_regs[] = {LEVEL_BASE::REG_RDI, LEVEL_BASE::REG_RSI, LEVEL_BASE::REG_RDX,
                                            LEVEL_BASE::REG_RCX, LEVEL_BASE::REG_R8, LEVEL_BASE::REG_R9};

const REG FBZergContext::return_reg = LEVEL_BASE::REG_RAX;

std::istream &FBZergContext::operator>>(std::istream &in) {
    ADDRINT tmp;
    std::vector < AllocatedArea * > allocs;
    for (REG reg : FBZergContext::argument_regs) {
        in.read((char *) &tmp, sizeof(tmp));
        if (tmp == AllocatedArea::MAGIC_VALUE) {
            AllocatedArea *aa = new AllocatedArea();
            values[reg] = (ADDRINT) aa;
            pointer_registers[reg] = aa;
            allocs.push_back(aa);
        } else {
            values[reg] = tmp;
        }
    }

    in.read((char *) &tmp, sizeof(tmp));
    if (tmp == AllocatedArea::MAGIC_VALUE) {
        AllocatedArea *aa = new AllocatedArea();
        values[return_reg] = (ADDRINT) aa;
        pointer_registers[return_reg] = aa;
        allocs.push_back(aa);
    } else {
        values[return_reg] = tmp;
    }

    for (auto aa : allocs) {
        in >> aa;
    }

    return in;
}

ADDRINT FBZergContext::get_value(REG reg) const {
    auto it = values.find(reg);
    if (it != values.end()) {
        return it->second;
    }

    return -1;
}

std::ostream &operator<<(std::ostream &out, const FBZergContext &ctx) {
    std::vector < AllocatedArea * > allocs;
    for (REG reg : FBZergContext::argument_regs) {
        AllocatedArea *aa = ctx.find_allocated_area(reg);
        if (aa != nullptr) {
            allocs.push_back(aa);
            out.write((const char *) &AllocatedArea::MAGIC_VALUE, sizeof(AllocatedArea::MAGIC_VALUE));
        } else {
            ADDRINT val = ctx.get_value(reg);
            out.write((const char *) &val, sizeof(val));
        }
    }

    auto it = ctx.pointer_registers.find(FBZergContext::return_reg);
    if (it != ctx.pointer_registers.end()) {
        allocs.push_back(it->second);
        out.write((const char *) &AllocatedArea::MAGIC_VALUE, sizeof(AllocatedArea::MAGIC_VALUE));
    } else {
        ADDRINT val = ctx.get_value(FBZergContext::return_reg);
        out.write((const char *) &val, sizeof(val));
    }

    for (AllocatedArea *aa : allocs) {
        out << aa;
    }

    return out;
}

FBZergContext &FBZergContext::operator=(const FBZergContext &orig) {
    for (auto it : pointer_registers) {
        delete it.second;
    }

    pointer_registers.clear();
    values.clear();

    for (auto it : orig.values) {
        AllocatedArea *aa = orig.find_allocated_area(it.first);
        if (aa == nullptr) {
            values[it.first] = it.second;
        } else {
            AllocatedArea *new_aa = new AllocatedArea();
            *new_aa = *aa;
            values[it.first] = (ADDRINT) new_aa;
            pointer_registers[it.first] = new_aa;
        }
    }

    return *this;
}

FBZergContext &FBZergContext::operator<<(CONTEXT *ctx) {
    for (REG reg : FBZergContext::argument_regs) {
        auto it = pointer_registers.find(reg);
        if (it == pointer_registers.end()) {
            values[reg] = PIN_GetContextReg(ctx, reg);
        }
    }

    void *ret_val = (void *) PIN_GetContextReg(ctx, FBZergContext::return_reg);
    if (PIN_CheckReadAccess(ret_val)) {

    }

    return *this;
}

AllocatedArea *FBZergContext::find_allocated_area(REG reg) const {
    auto it = pointer_registers.find(reg);
    if (it == pointer_registers.end()) {
        return nullptr;
    }

    return it->second;
}

void FBZergContext::reset_context(CONTEXT *ctx, const FBZergContext &orig) {
    for (REG reg : FBZergContext::argument_regs) {
        AllocatedArea *aa = find_allocated_area(reg);
        if (aa == nullptr) {
            PIN_SetContextReg(ctx, reg, orig.get_value(reg));
        }
    }

    for (std::map<REG, AllocatedArea *>::iterator it = pointer_registers.begin(); it != pointer_registers.end(); ++it) {
        it->second->reset();
        PIN_SetContextReg(ctx, it->first, it->second->getAddr());
    }
}

void FBZergContext::add(REG reg, AllocatedArea *aa) {
    pointer_registers[reg] = aa;
    values[reg] = (ADDRINT) aa;
}

void FBZergContext::add(REG reg, ADDRINT value) {
    values[reg] = value;
}

FBZergContext::~FBZergContext() {
    for (auto it : pointer_registers) {
        delete it.second;
    }
}