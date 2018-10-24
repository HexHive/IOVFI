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
    ss << "Argument Count Test at 0x" << std::hex << location_;
    return ss.str();
}

int fbf::ArgumentCountTestCase::run_test() {
    alarm(0);

    int64_t count = 0;
    cs_insn *insn;
    uint64_t curr_loc;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;

    std::vector<uintptr_t> jmp_tgts;
    jmp_tgts.push_back(location_);

    std::map<uint16_t, bool> reg_read;
    std::map<uint16_t, bool> reg_written;
    std::set<uintptr_t> visited;
    std::set<uint16_t> regs_used_in_args;
    std::set<uint16_t> determined_regs;

    std::vector<int64_t> syscall_vals;
    syscall_vals.push_back(INVALID_SYSCALL_VAL);

    while (!jmp_tgts.empty()) {
        curr_loc = jmp_tgts.back();

        LOG_DEBUG << "curr_loc = " << std::hex << curr_loc;

        std::pair<std::string, size_t> curr_func = binDesc_.getSym(curr_loc);
        LOG_DEBUG << "curr_func: " << curr_func.first << " size: " << curr_func.second;

        uintptr_t start_loc = binDesc_.getSymLocation(curr_func);
        if (start_loc == (uintptr_t) -1) {
            /* Hidden visibility function, so we don't have its location */
            LOG_DEBUG << "Hidden visibility";
            start_loc = curr_loc;
        }

        do {
            int64_t size = curr_func.second - (curr_loc - start_loc);
            count = cs_disasm(handle_, (uint8_t *) curr_loc, size, curr_loc, 1, &insn);
            if (count > 0) {
                visited.insert(curr_loc);

                cs_x86 x86 = insn->detail->x86;

                if(insn->id == X86_INS_SYSCALL) {
                    if(syscall_vals.back() == 0) {
                        LOG_DEBUG << curr_func.first << " uses unknown syscall";
                    } else {
                        int syscall_val_count = 0;
                        for(int j = syscall_vals.size() - 1; syscall_vals[j] != INVALID_SYSCALL_VAL; j--) {
                            syscall_val_count++;
                        }
                        std::stringstream ss;
                        ss << curr_func.first << " uses syscall with "
                                << syscall_val_count << " potential targets: [ ";
                        for(int j = syscall_vals.size() - 1; syscall_vals[j] != INVALID_SYSCALL_VAL; j--) {
                            ss << "0x" << std::hex << syscall_vals[j] << " ";
                        }
                        ss << "]";

                        LOG_DEBUG << ss.str();

                        while(syscall_vals.back() != INVALID_SYSCALL_VAL) {
                            std::set<uint16_t> syscall_regs = binDesc_.getSyscallRegisters(syscall_vals.back());
                            for(uint16_t syscall_reg : syscall_regs) {
                                uint16_t reg = get_reg_id(syscall_reg);
                                reg_read[reg] = true;
                                if (reg_used_as_arg(reg) &&
                                    reg_written.find(reg) == reg_written.end()) {
                                    regs_used_in_args.insert(reg);
                                    determined_regs.insert(reg);
                                }
                            }

                            syscall_vals.pop_back();
                        }
                    }
                }

                if (cs_regs_access(handle_, insn, regs_read, &regs_read_count, regs_write, &regs_write_count) == 0) {
                    /* Special case for xor reg_a, reg_a since it is so common but is technically
                     * a read before a write */
                    if ((insn->id != X86_INS_XOR && insn->id != X86_INS_XORPS && insn->id != X86_INS_XORPD) ||
                        regs_read_count != 1) {
                        for (int i = 0; i < regs_read_count; i++) {
                            uint16_t reg = get_reg_id(regs_read[i]);
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
                        uint16_t reg = get_reg_id(regs_write[i]);
                        if(reg == X86_REG_RAX) {
                            for(int j = 0; j < x86.op_count; j++) {
                                if(x86.operands[j].type == X86_OP_IMM && x86.operands[j].imm > INVALID_SYSCALL_VAL) {
                                    syscall_vals.push_back(x86.operands[j].imm);
                                }
                            }
                        }

                        reg_written[reg] = true;
                        if (reg_used_as_arg(reg) && reg_read.find(reg) == reg_read.end()) {
                            bool found = false;
                            for (int j = 0; j < NUM_ARG_REGS; j++) {
                                if (REG_ABI_ORDER[j] == reg) {
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
                for(uint8_t i = 0; i < insn->detail->groups_count && !insn_is_jmp_type; i++) {
                    if(insn->detail->groups[i] == X86_GRP_JUMP) {
                        insn_is_jmp_type = true;
                    }
                }
                if (insn_is_jmp_type) {
                    uintptr_t loc = 0;
                    std::stringstream addr_str;
                    addr_str << std::hex << insn->op_str;
                    addr_str >> loc;
                    /* loc == 0 implies an indirect call, ignore for now... */
                    if (loc > 0 && visited.find(loc) == visited.end()) {
                        if(insn->id == X86_INS_CALL) {
                            syscall_vals.push_back(INVALID_SYSCALL_VAL);
                        }
                        if(insn->id != X86_INS_JMP) {
                            /* Return back to the next instruction */
                            jmp_tgts.back() = insn->address + insn->size;
                        }

                        /* Follow jump targets */
                        jmp_tgts.push_back(loc);
                        cs_free(insn, count);
                        count = -1;
                        break;
                    } else if(insn->id != X86_INS_JMP){
                        /* We have either visited the jump target or we don't know where we
                         * are going. Go onto the next instruction if the current instruction
                         * is not an unconditional jump */
                        curr_loc = insn->address + insn->size;
                    } else {
                        /* This is an unconditional jump to a target we have already analyzed,
                         * so we're done */
                        cs_free(insn, count);
                        count = 0;
                        break;
                    }
                } else {
                    curr_loc = insn->address + insn->size;
                }
            }
            cs_free(insn, count);
            if (visited.find(curr_loc) != visited.end()) {
                count = 0;
            }
        } while (count > 0 && determined_regs.size() < NUM_ARG_REGS);

        if (count <= 0) {
            if(count == 0) {
                jmp_tgts.pop_back();
                while (syscall_vals.back() != INVALID_SYSCALL_VAL) {
                    syscall_vals.pop_back();
                }
                syscall_vals.pop_back();
            }
        } else if (determined_regs.size() >= NUM_ARG_REGS) {
            break;
        }
    }

    arg_count_ = regs_used_in_args.size();
    LOG_DEBUG << arg_count_ << " registers used in " << binDesc_.getSym(location_).first << " to pass arguments:";
    for(auto reg : regs_used_in_args) {
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

uint64_t fbf::ArgumentCountTestCase::get_value() {
    return arg_count_;
}

uintptr_t fbf::ArgumentCountTestCase::get_location() {
    return location_;
}
