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

fbf::ArgumentCountTestCase::ArgumentCountTestCase(uintptr_t location, size_t size, BinaryDescriptor& binDesc) :
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

    while(!jmp_tgts.empty()) {
        curr_loc = jmp_tgts.back();
        std::pair<std::string, size_t> curr_func = binDesc_.getSym(jmp_tgts.back());
        visited.insert(curr_loc);
        uintptr_t start_loc = binDesc_.getSymLocation(curr_func);
        if(start_loc == (uintptr_t)-1) {
            std::stringstream msg;
            msg << "Could not find location for " << curr_func.first;
            throw std::runtime_error(msg.str());
        }

        do {
            int64_t size = curr_func.second - (curr_loc - start_loc);
            count = cs_disasm(handle_, (uint8_t *)curr_loc, size, curr_loc, 1, &insn);
            if (count > 0) {
                if (cs_regs_access(handle_, insn, regs_read, &regs_read_count, regs_write, &regs_write_count) == 0) {
                    for (int i = 0; i < regs_write_count; i++) {
                        uint16_t reg = get_reg_id(regs_write[i]);
                        reg_written[reg] = true;
                    }

                    for (int i = 0; i < regs_read_count; i++) {
                        uint16_t reg = get_reg_id(regs_read[i]);
                        reg_read[reg] = true;
                        if (reg_used_as_arg(reg) &&
                            reg_written.find(reg) == reg_written.end()) {
                            for (int j = 0; j < sizeof(REG_ABI_ORDER); j++) {
                                regs_used_in_args.insert(REG_ABI_ORDER[j]);
                                if (REG_ABI_ORDER[j] == reg) {
                                    break;
                                }
                            }
                        }
                    }
                }

                if (insn->id == X86_INS_JMP) {
                    uintptr_t loc;
                    std::stringstream addr_str;
                    addr_str << std::hex << insn->op_str;
                    addr_str >> loc;
                    
                    if(visited.find(loc) == visited.end()) {
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
        } while (count > 0);

        if(count <= 0) {
            jmp_tgts.pop_back();
        }
    }

    arg_count_ = regs_used_in_args.size();

    return fbf::ITestCase::PASS;
}

bool fbf::ArgumentCountTestCase::reg_used_as_arg(uint16_t reg) {
    switch (reg) {
        case X86_REG_RDI:
        case X86_REG_EDI:
        case X86_REG_DI:

        case X86_REG_RSI:
        case X86_REG_ESI:

        case X86_REG_RDX:
        case X86_REG_EDX:
        case X86_REG_DX:

        case X86_REG_RCX:
        case X86_REG_ECX:
        case X86_REG_CX:

        case X86_REG_R8:
        case X86_REG_R9:
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
