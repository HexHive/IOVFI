//
// Created by derrick on 10/7/18.
//

#include <fosbin-sleuth/argumentCountTestCase.h>

#include "fosbin-sleuth/argumentCountTestCase.h"
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include <iostream>
#include <cstring>
#include <unistd.h>

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

    size_t count;
    cs_insn *insn;
    uint64_t curr_loc = (uint64_t) location_;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;

    std::vector<uintptr_t> jmp_tgts;
    jmp_tgts.push_back(location_);

    std::map<uint16_t, bool> reg_read;
    std::map<uint16_t, bool> reg_written;
    std::set<uintptr_t> visited;
    std::set<uint16_t> regs_used_in_args;
    std::set<uint16_t> determined_regs;

    while (!jmp_tgts.empty()) {
        curr_loc = jmp_tgts.back();

        std::pair<std::string, size_t> curr_func = binDesc_.getSym(curr_loc);
        uintptr_t start_loc = binDesc_.getSymLocation(curr_func);
        if (start_loc == (uintptr_t) -1) {
            /* Hidden visibility function, so we don't have its location */
            start_loc = curr_loc;
        }

        do {
            int64_t size = curr_func.second - (curr_loc - start_loc);
            count = cs_disasm(handle_, (uint8_t *) curr_loc, size, curr_loc, 1, &insn);
            if (count > 0) {
                visited.insert(curr_loc);

                if (cs_regs_access(handle_, insn, regs_read, &regs_read_count, regs_write, &regs_write_count) == 0) {
                    /* Special case for xor reg_a, reg_a since it is so common */
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

                if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
                    uintptr_t loc = 0;
                    std::stringstream addr_str;
                    addr_str << std::hex << insn->op_str;
                    addr_str >> loc;
                    /* loc == 0 implies an indirect call, ignore for now... */
                    if (loc > 0 && visited.find(loc) == visited.end()) {
                        jmp_tgts.back() = insn->address + insn->size;
                        jmp_tgts.push_back(loc);
                        cs_free(insn, count);
                        break;
                    } else {
                        curr_loc = insn->address + insn->size;
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
            jmp_tgts.pop_back();
        } else if (determined_regs.size() >= NUM_ARG_REGS) {
            break;
        }
    }

    arg_count_ = regs_used_in_args.size();

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
