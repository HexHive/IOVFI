//
// Created by derrick on 12/27/18.
//

const REG FBZergContext::argument_regs[] = {LEVEL_BASE::REG_RDI, LEVEL_BASE::REG_RSI, LEVEL_BASE::REG_RDX,
                                            LEVEL_BASE::REG_RCX, LEVEL_BASE::REG_R8, LEVEL_BASE::REG_R9};

const REG FBZergContext::return_reg = LEVEL_BASE::REG_RAX;


FBZergContext::FBZergContext() {
    return_value = 0x00;
}

std::istream &operator>>(std::istream &in, FBZergContext &ctx) {
    ADDRINT tmp;
    std::map < REG, AllocatedArea * > allocs;
    ctx.pointer_registers.clear();
    ctx.values.clear();
    for (REG reg : FBZergContext::argument_regs) {
        in.read((char *) &tmp, sizeof(tmp));
        if (in.eof()) {
            log_error("Could not read all context bytes");
        }
        if (tmp == AllocatedArea::MAGIC_VALUE) {
            AllocatedArea *aa = new AllocatedArea();
            ctx.pointer_registers[reg] = aa;
            allocs[reg] = aa;
        } else {
            ctx.values[reg] = tmp;
        }
    }

    in.read((char *) &tmp, sizeof(tmp));
    in.read((char *) &ctx.return_value, sizeof(ctx.return_value));
    ctx.values[FBZergContext::return_reg] = tmp;

    for (auto aa : allocs) {
        in >> aa.second;
        ctx.values[aa.first] = (ADDRINT) aa.second->getAddr();
    }

    size_t syscall_count = 0;
    in.read((char *) &syscall_count, sizeof(syscall_count));
    ctx.system_calls.clear();
    while (syscall_count > 0) {
        ADDRINT syscall;
        in.read((char *) &syscall, sizeof(syscall));
        ctx.system_calls.insert(syscall);
        syscall_count--;
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

bool FBZergContext::return_is_ptr() const {
    ADDRINT ret_val = get_value(FBZergContext::return_reg);
    if(ret_val == AllocatedArea::MAGIC_VALUE) {
        return true;
    }

    ret_val = sign_extend(ret_val);
    return PIN_CheckReadAccess((void *) ret_val);
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
    out.write((const char *) &ctx.return_value, sizeof(ctx.return_value));

    for (AllocatedArea *aa : allocs) {
        out << aa;
    }

    size_t syscall_size = ctx.system_calls.size();
    out.write((const char *) &syscall_size, sizeof(syscall_size));
    for (ADDRINT i : ctx.system_calls) {
        out.write((const char *) &i, sizeof(ADDRINT));
    }

    return out;
}

int64_t FBZergContext::sign_extend(int64_t orig) const {
    /* First check that the upper 4 bytes are all zero */
    if ((orig >> 32) == 0) {
        /* Get the int sign bit */
        bool is_negative = (((orig & 0x00000000FFFFFFFF) >> 31) == 1);
        /* Next extend the sign if needed */
        if (is_negative) {
            orig |= (0xFFFFFFFF00000000);
        }
    }

    return orig;
}

bool FBZergContext::return_values_equal(const FBZergContext &ctx) const {
    if ((return_is_ptr() && !ctx.return_is_ptr()) ||
        (!return_is_ptr() && ctx.return_is_ptr())) {
        return false;
    }

    if (return_is_ptr()) {
        return true;
    }
    
    int64_t this_ret_val = (int64_t) get_value(FBZergContext::return_reg);
    int64_t that_ret_val = (int64_t) ctx.get_value(FBZergContext::return_reg);

    if (this_ret_val == that_ret_val) {
        return true;
    }

    /* Force a sign extension as a heuristic for functions that return 32-bit values */
    this_ret_val = sign_extend(this_ret_val);
    that_ret_val = sign_extend(that_ret_val);

    if ((this_ret_val < 0 && that_ret_val < 0) || (this_ret_val > 0 && that_ret_val > 0)) {
        return true;
    }

    return false;
}

bool FBZergContext::operator==(const FBZergContext &ctx) const {
    if (!return_values_equal(ctx)) {
        return false;
    }

    if(system_calls.size() != ctx.system_calls.size()) {
        return false;
    }
    
    for (ADDRINT i : system_calls) {
        if (ctx.system_calls.find(i) == ctx.system_calls.end()) {
            return false;
        }
    }

    for (auto it : pointer_registers) {
        AllocatedArea *aa = ctx.find_allocated_area(it.first);
        if (aa == nullptr) {
            log_message("Expected AllocatedArea is missing");
            return false;
        }

        if (*aa != *it.second) {
            log_message("AllocatedAreas are not the same");
            return false;
        }
    }

    return true;
}

bool FBZergContext::operator!=(const FBZergContext &ctx) const {
    return !(*this == ctx);
}

FBZergContext &FBZergContext::operator=(const FBZergContext &orig) {
    for (auto it : pointer_registers) {
        delete it.second;
    }
    pointer_registers.clear();
    values.clear();
    return_value = orig.return_value;
    system_calls = orig.system_calls;

    for (auto it : orig.values) {
        AllocatedArea *aa = orig.find_allocated_area(it.first);
        if (aa == nullptr) {
            values[it.first] = orig.get_value(it.first);
        } else {
            AllocatedArea *new_aa = new AllocatedArea(*aa);
            values[it.first] = new_aa->getAddr();
            pointer_registers[it.first] = new_aa;
        }
    }

    return *this;
}

void FBZergContext::prettyPrint() const {
    std::stringstream ss;
    prettyPrint(ss);
    log_message(ss);
}

void FBZergContext::prettyPrint(std::ostream &s) const {
    for (REG reg : argument_regs) {
        s << REG_StringShort(reg) << "\t= " << std::hex << get_value(reg) << std::endl;
    }

    s << REG_StringShort(FBZergContext::return_reg) << "\t= " << std::hex
      << get_value(FBZergContext::return_reg) << std::endl;

    for (auto it : pointer_registers) {
        it.second->prettyPrint(s, 1);
    }
}

CONTEXT *FBZergContext::operator>>(CONTEXT *ctx) const {
    for (REG reg : FBZergContext::argument_regs) {
        PIN_SetContextReg(ctx, reg, get_value(reg));
    }
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
        PIN_SafeCopy(&return_value, ret_val, sizeof(return_value));
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

void FBZergContext::reset_non_ptrs(const FBZergContext &ctx) {
    for (auto it : pointer_registers) {
        AllocatedArea *aa = ctx.find_allocated_area(it.first);
        if (aa != nullptr) {
            it.second->reset_non_ptrs(*aa);
        }
    }
}

void FBZergContext::add(REG reg, AllocatedArea *aa) {
    if (pointer_registers.find(reg) == pointer_registers.end()) {
        pointer_registers[reg] = aa;
        values[reg] = aa->getAddr();
    } else {
        pointer_registers[reg] = aa;
        values[reg] = aa->getAddr();
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

const std::set <ADDRINT> FBZergContext::get_syscalls() const {
    return system_calls;
}

void FBZergContext::set_syscalls(const std::set <ADDRINT> syscalls) {
    system_calls = syscalls;
}
