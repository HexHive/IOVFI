//
// Created by derrick on 10/7/18.
//

#include <fosbin-sleuth/argumentCountTestCase.h>

fbf::ArgumentCountTestCase::ArgumentCountTestCase(uintptr_t location, size_t size, BinaryDescriptor &binDesc) :
        ITestCase(), location_(location), size_(size), arg_count_(0), handle_(0), binDesc_(binDesc) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
        throw std::runtime_error("Could not open capstone handle");
    }
    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
}

fbf::ArgumentCountTestCase::~ArgumentCountTestCase() {
    if (handle_ != 0) {
        cs_close(&handle_);
    }
}

const std::string fbf::ArgumentCountTestCase::get_test_name() {
    std::stringstream ss;
    const LofSymbol& curr_func = binDesc_.getFunc(location_);

    if (curr_func.size == 0) {
        ss << "Argument Count Test at 0x" << std::hex << location_;
    } else {
        ss << "Argument Count Test for " << curr_func.name << " (0x" << std::hex << location_ << ")";
    }
    return ss.str();
}

int fbf::ArgumentCountTestCase::run_test() {
    alarm(0);

    int64_t count = 0;
    cs_insn *insn;
    uint64_t curr_loc;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;
    bool first_determined_regs = true;

    typedef uint16_t register_t;

    typedef struct register_state {
        std::vector<int64_t> syscall_values;
        std::set<register_t> regs_used_in_args;
        std::set<register_t> determined_regs;
        std::map<register_t, bool> reg_read;
        std::map<register_t, bool> reg_written;
    } register_state;

    std::vector<std::pair<uintptr_t, register_state>> register_states;
    register_state initial_state;

    register_states.push_back(std::make_pair(location_, initial_state));

    std::set<uintptr_t> visited;
    std::set<register_t> all_regs_used_in_args;
    std::set<register_t> all_determined_regs;

    while (!register_states.empty()) {
        curr_loc = register_states.back().first;
        std::vector<int64_t> &syscall_vals = register_states.back().second.syscall_values;
        std::set<register_t> &regs_used_in_args = register_states.back().second.regs_used_in_args;
        std::set<register_t> &determined_regs = register_states.back().second.determined_regs;
        std::map<register_t, bool> &reg_written = register_states.back().second.reg_written;
        std::map<register_t, bool> &reg_read = register_states.back().second.reg_read;

        LOG_DEBUG << "curr_loc = " << std::hex << curr_loc;

        const LofSymbol& curr_func = binDesc_.getSym(curr_loc);
        LOG_DEBUG << "curr_func: " << curr_func.name << " size: " << curr_func.size;

        uintptr_t start_loc = binDesc_.getSymLocation(curr_func);
        if (start_loc == (uintptr_t) -1) {
            /* Hidden visibility function, so we don't have its location */
            LOG_DEBUG << "Hidden visibility";
            start_loc = curr_loc;
        }

        bool jump = false;
        bool pop_state = false;
        do {
            jump = false;
            pop_state = false;
            int64_t size = curr_func.size - (curr_loc - start_loc);
            count = cs_disasm(handle_, (uint8_t *) curr_loc, size, curr_loc, 1, &insn);
            if (count > 0) {
                visited.insert(curr_loc);

                cs_x86 x86 = insn->detail->x86;

                if (insn->id == X86_INS_SYSCALL) {
                    if (syscall_vals.back() == 0) {
                        LOG_DEBUG << curr_func.name << " uses unknown syscall";
                    } else {
                        std::stringstream ss;
                        ss << curr_func.name << " uses syscall with "
                           << syscall_vals.size() << " potential targets: [ ";
                        for (int64_t val : syscall_vals) {
                            ss << "0x" << std::hex << val << " ";
                        }
                        ss << "]";

                        LOG_DEBUG << ss.str();

//                        while (syscall_vals.back() != INVALID_SYSCALL_VAL) {
                        std::set<register_t> syscall_regs = binDesc_.getSyscallRegisters(syscall_vals.back());
                        for (register_t syscall_reg : syscall_regs) {
                            register_t reg = get_reg_id(syscall_reg);
                            reg_read[reg] = true;
                            if (reg_used_as_arg(reg) &&
                                reg_written.find(reg) == reg_written.end()) {
                                regs_used_in_args.insert(reg);
                                determined_regs.insert(reg);
                            }
                        }

                        syscall_vals.pop_back();
//                        }
                    }
                }

                if (cs_regs_access(handle_, insn, regs_read, &regs_read_count, regs_write, &regs_write_count) == 0) {
                    /* Special case for xor reg_a, reg_a since it is so common but is technically
                     * a read before a write */
                    if ((insn->id != X86_INS_XOR && insn->id != X86_INS_XORPS && insn->id != X86_INS_XORPD) ||
                        regs_read_count != 1) {
                        for (int i = 0; i < regs_read_count; i++) {
                            register_t reg = get_reg_id(regs_read[i]);
                            reg_read[reg] = true;
                            if (reg_used_as_arg(reg) &&
                                reg_written.find(reg) == reg_written.end()) {
                                /* Floating point arguments are passed in the XMM* registers.
                                 * They are used as needed, and it is not easily determined which
                                 * argument the register is being used for.  Example: foo(int, int, float)
                                 * will use XMM0 to pass the last argument, not, for instance XMM2 because
                                 * it is the third argument.
                                 */
                                if (is_floating_reg(reg)) {
                                    determined_regs.insert(reg);
                                    regs_used_in_args.insert(reg);
                                } else {
                                    for (int j = 0; j < NUM_ARG_REGS; j++) {
                                        regs_used_in_args.insert(REG_ABI_ORDER[j]);
                                        determined_regs.insert(REG_ABI_ORDER[j]);
                                        if (REG_ABI_ORDER[j] == reg) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    for (int i = 0; i < regs_write_count; i++) {
                        register_t reg = get_reg_id(regs_write[i]);
                        if (reg == X86_REG_RAX) {
                            for (int j = 0; j < x86.op_count; j++) {
                                if (x86.operands[j].type == X86_OP_IMM && x86.operands[j].imm > INVALID_SYSCALL_VAL) {
                                    syscall_vals.push_back(x86.operands[j].imm);
                                }
                            }
                        }

                        reg_written[reg] = true;
                        if (reg_used_as_arg(reg) && reg_read.find(reg) == reg_read.end()) {
                            bool found = false;
                            for (int j = 0; j < NUM_ARG_REGS; j++) {
                                if (REG_ABI_ORDER[j] == reg || FLOAT_REG_ABI_ORDER[j] == reg) {
                                    found = true;
                                }

                                if (found) {
                                    determined_regs.insert(REG_ABI_ORDER[j]);
                                }
                            }
                        }
                    }
                }

                bool insn_is_jmp_type = (insn->id == X86_INS_CALL);
                bool insn_is_ret_type = false;
                for (uint8_t i = 0; i < insn->detail->groups_count && (!insn_is_jmp_type || !insn_is_ret_type); i++) {
                    if (insn->detail->groups[i] == X86_GRP_JUMP) {
                        insn_is_jmp_type = true;
                    } else if (insn->detail->groups[i] == X86_GRP_RET) {
                        insn_is_ret_type = true;
                    }
                }
                if (insn_is_jmp_type) {
                    uintptr_t loc = 0;
                    std::stringstream addr_str;
                    addr_str << std::hex << insn->op_str;
                    addr_str >> loc;
                    /* loc == 0 implies an indirect call, ignore for now... */
                    if (loc > 0 && visited.find(loc) == visited.end()) {
//                        if (insn->id == X86_INS_CALL) {
//                            syscall_vals.push_back(INVALID_SYSCALL_VAL);
//                        }
                        if (insn->id != X86_INS_JMP) {
                            /* Return back to the next instruction */
                            register_states.back().first = insn->address + insn->size;
                        } else if (register_states.size() > 1) {
                            /* This is an unconditional jump, so do not return to this block */
                            register_states.pop_back();
                        }

                        /* Follow jump targets */
                        register_states.push_back(std::make_pair(loc, register_states.back().second));
                        curr_loc = loc;
                        jump = true;
                    } else if (insn->id != X86_INS_JMP) {
                        /* We have either visited the jump target or we don't know where we
                         * are going. Go onto the next instruction if the current instruction
                         * is not an unconditional jump */
                        curr_loc = insn->address + insn->size;
                    } else {
                        /* This is an unconditional jump to a target we have already analyzed,
                         * so we're done */
                        pop_state = true;
                        break;
                    }
                } else if (insn_is_ret_type) {
                    jump = true;
                    pop_state = true;
                    break;
                } else {
                    curr_loc = insn->address + insn->size;
                }
            }
            cs_free(insn, count);
            if (visited.find(curr_loc) != visited.end()) {
                pop_state = true;
                jump = true;
            }
        } while (count > 0 && !jump && determined_regs.size() < NUM_ARG_REGS);

        if (determined_regs.size() >= NUM_ARG_REGS || count == 0) {
            pop_state = true;
        }

        if (pop_state) {
            for (register_t reg : register_states.back().second.regs_used_in_args) {
                all_regs_used_in_args.insert(reg);
            }
            std::set<register_t> intersect;
            if (first_determined_regs) {
                intersect = register_states.back().second.determined_regs;
                first_determined_regs = false;
            } else {
                std::set_intersection(all_determined_regs.begin(), all_determined_regs.end(),
                                      determined_regs.begin(), determined_regs.end(),
                                      std::inserter(intersect, intersect.begin()));
            }
            all_determined_regs = intersect;

            register_states.pop_back();
        }

        if (all_determined_regs.size() >= NUM_ARG_REGS) {
            break;
        }
    }

    arg_count_ = all_regs_used_in_args.size();
    LOG_DEBUG << arg_count_ << " registers used in " << binDesc_.getSym(location_).name << " to pass arguments:";
    for (auto reg : all_regs_used_in_args) {
        LOG_DEBUG << cs_reg_name(handle_, reg);
    }

    return fbf::ITestCase::PASS;
}

bool fbf::ArgumentCountTestCase::is_floating_reg(uint16_t reg) {
    switch (reg) {
        case X86_REG_XMM0:
        case X86_REG_XMM1:
        case X86_REG_XMM2:
        case X86_REG_XMM3:
        case X86_REG_XMM4:
        case X86_REG_XMM5:
        case X86_REG_XMM6:
        case X86_REG_XMM7:
            return true;
        default:
            return false;
    }
}

bool fbf::ArgumentCountTestCase::reg_used_as_arg(uint16_t reg) {
    switch (reg) {
        case X86_REG_RDI:
        case X86_REG_EDI:
        case X86_REG_DI:
        case X86_REG_XMM0:

        case X86_REG_RSI:
        case X86_REG_ESI:
        case X86_REG_XMM1:

        case X86_REG_RDX:
        case X86_REG_EDX:
        case X86_REG_DX:
        case X86_REG_XMM2:

        case X86_REG_RCX:
        case X86_REG_ECX:
        case X86_REG_CX:
        case X86_REG_XMM3:

        case X86_REG_R8:
        case X86_REG_XMM4:

        case X86_REG_R9:
        case X86_REG_XMM5:
            return true;

        default:
            return false;
    }
}

uint16_t fbf::ArgumentCountTestCase::get_reg_id(uint16_t reg) {
    switch (reg) {
        case X86_REG_RDI:
        case X86_REG_EDI:
        case X86_REG_DI:
            return X86_REG_RDI;

        case X86_REG_RSI:
        case X86_REG_ESI:
            return X86_REG_RSI;

        case X86_REG_RDX:
        case X86_REG_EDX:
        case X86_REG_DX:
            return X86_REG_RDX;

        case X86_REG_RCX:
        case X86_REG_ECX:
        case X86_REG_CX:
            return X86_REG_RCX;

        case X86_REG_R8:
            return X86_REG_R8;

        case X86_REG_R9:
            return X86_REG_R9;

        case X86_REG_RAX:
        case X86_REG_AX:
        case X86_REG_EAX:
            return X86_REG_RAX;

        default:
            return reg;
    }
}

uintptr_t fbf::ArgumentCountTestCase::get_location() {
    return location_;
}
