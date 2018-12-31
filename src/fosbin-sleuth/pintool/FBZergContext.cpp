//
// Created by derrick on 12/27/18.
//

#include "pin.H"

const REG FBZergContext::argument_regs[] = {LEVEL_BASE::REG_RDI, LEVEL_BASE::REG_RSI, LEVEL_BASE::REG_RDX,
                                            LEVEL_BASE::REG_RCX, LEVEL_BASE::REG_R8, LEVEL_BASE::REG_R9};

const REG FBZergContext::return_reg = LEVEL_BASE::REG_RAX;

FBZergContext::FBZergContext() {}

std::istream &operator>>(std::istream &in, FBZergContext &ctx) {
    ADDRINT tmp;
    std::vector < AllocatedArea * > allocs;
    for (REG reg : FBZergContext::argument_regs) {
        in.read((char *) &tmp, sizeof(tmp));
//        std::cout << "Read in " << REG_StringShort(reg) << " = " << std::hex << tmp << std::endl;
        if (tmp == AllocatedArea::MAGIC_VALUE) {
            AllocatedArea *aa = new AllocatedArea();
            ctx.values[reg] = (ADDRINT) aa;
            ctx.pointer_registers[reg] = aa;
            allocs.push_back(aa);
        } else {
            ctx.values[reg] = tmp;
        }
    }

    in.read((char *) &tmp, sizeof(tmp));
//    std::cout << "Read in " << REG_StringShort(FBZergContext::return_reg) << " = " << std::hex << tmp << std::endl;
//    if (tmp == AllocatedArea::MAGIC_VALUE) {
//        AllocatedArea *aa = new AllocatedArea();
//        ctx.values[FBZergContext::return_reg] = (ADDRINT) aa;
//        ctx.pointer_registers[FBZergContext::return_reg] = aa;
//        allocs.push_back(aa);
//    } else {
        ctx.values[FBZergContext::return_reg] = tmp;
//    }

    for (auto aa : allocs) {
        in >> aa;
    }
//    std::cout << "Done reading in context\n" << std::endl;

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
//            std::cout << "Writing " << REG_StringShort(reg) << " value " << std::hex << AllocatedArea::MAGIC_VALUE << std::endl;
            allocs.push_back(aa);
            out.write((const char *) &AllocatedArea::MAGIC_VALUE, sizeof(AllocatedArea::MAGIC_VALUE));
        } else {
            ADDRINT val = ctx.get_value(reg);
//            std::cout << "Writing " << REG_StringShort(reg) << " value " << std::hex << val << std::endl;
            out.write((const char *) &val, sizeof(val));
        }
    }

    auto it = ctx.pointer_registers.find(FBZergContext::return_reg);
    if (it != ctx.pointer_registers.end()) {
        allocs.push_back(it->second);
//        std::cout << "Writing " << REG_StringShort(FBZergContext::return_reg) << " value " << std::hex << AllocatedArea::MAGIC_VALUE << std::endl;
        out.write((const char *) &AllocatedArea::MAGIC_VALUE, sizeof(AllocatedArea::MAGIC_VALUE));
    } else {
        ADDRINT val = ctx.get_value(FBZergContext::return_reg);
//        std::cout << "Writing " << REG_StringShort(FBZergContext::return_reg) << " value " << std::hex << val << std::endl;
        out.write((const char *) &val, sizeof(val));
    }

    for (AllocatedArea *aa : allocs) {
        out << aa;
    }

    return out;
}

bool FBZergContext::operator==(const FBZergContext &ctx) const {
    if (get_value(FBZergContext::return_reg) != ctx.get_value(FBZergContext::return_reg)) {
//        std::cout << "Contexts return values mismatch:" << std::endl;
//        std::cout << "This " << REG_StringShort(FBZergContext::return_reg) << " = " << std::hex << get_value(FBZergContext::return_reg) << std::endl;
//        std::cout << "That " << REG_StringShort(FBZergContext::return_reg) << " = " << std::hex << ctx.get_value(FBZergContext::return_reg) << std::endl;

        return false;
    }

    for (auto it : pointer_registers) {
        AllocatedArea *aa = ctx.find_allocated_area(it.first);
        if (aa == nullptr) {
//            std::cout << "Expected AllocatedArea is missing" << std::endl;
            return false;
        }

        if (*aa != *it.second) {
//            std::cout << "AllocatedAreas are not the same" << std::endl;
            return false;
        }
    }

    return true;
}

bool FBZergContext::operator!=(const FBZergContext &ctx) const {
    return !(*this == ctx);
}

FBZergContext &FBZergContext::operator=(const FBZergContext &orig) {
//    std::cout << "Deleting allocated areas" << std::endl;
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

void FBZergContext::prettyPrint() const {
    for (REG reg : argument_regs) {
        std::cout << REG_StringShort(reg) << "\t= " << std::hex << get_value(reg) << std::endl;
    }

    std::cout << REG_StringShort(FBZergContext::return_reg) << "\t= " << std::hex
              << get_value(FBZergContext::return_reg) << std::endl;

    for (auto it : pointer_registers) {
        it.second->prettyPrint(1);
    }
}

CONTEXT *FBZergContext::operator>>(CONTEXT *ctx) const {
//    std::cout << "Setting context" << std::endl;
    for (REG reg : FBZergContext::argument_regs) {
        PIN_SetContextReg(ctx, reg, get_value(reg));
    }

//    displayCurrentContext(ctx);
    return ctx;
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
//        std::cout << "ret_val (" << std::hex << ret_val << ") is readable" << std::endl;
//        AllocatedArea *aa = find_allocated_area(FBZergContext::return_reg);
//        if(aa != nullptr) {
//            delete aa;
//        }
//        aa = new AllocatedArea(ret_val);
//
//        values[FBZergContext::return_reg] = (ADDRINT)aa;
//        pointer_registers[FBZergContext::return_reg] = aa;
        values[FBZergContext::return_reg] = AllocatedArea::MAGIC_VALUE;
    } else {
        values[FBZergContext::return_reg] = (ADDRINT) ret_val;
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
//    std::cout << "Adding AllocatedArea to register " << REG_StringShort(reg) << std::endl;
    if (pointer_registers.find(reg) == pointer_registers.end()) {
        pointer_registers[reg] = aa;
        values[reg] = (ADDRINT) aa;
    } else {
//        std::cout << "Resetting AllocatedArea" << std::endl;
        *pointer_registers[reg] = *aa;
    }
}

void FBZergContext::add(REG reg, ADDRINT value) {
    values[reg] = value;
}

FBZergContext::~FBZergContext() {
    for (auto it : pointer_registers) {
        delete it.second;
    }
}