//
// Created by derrick on 10/7/18.
//

#include <fosbin-sleuth/argumentCountTestCase.h>

#include "fosbin-sleuth/argumentCountTestCase.h"
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include <iostream>
#include <cstring>

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
    size_t count;
    cs_insn *insn;
    uint64_t curr_loc = (uint64_t) location_;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;

    std::vector<std::pair<std::string, size_t>> jmp_tgts;
    jmp_tgts.push_back(binDesc_.getSym(location_));

    std::map<uint16_t, bool> reg_read;
    std::map<uint16_t, bool> reg_written;
    std::set<std::pair<std::string, size_t>> visited;
    std::set<uint16_t> regs_used_in_args;

    while(!jmp_tgts.empty()) {
        std::pair<std::string, size_t> curr_func = jmp_tgts.back();
        visited.insert(curr_func);
        uintptr_t start_loc = binDesc_.getSymLocation(curr_func);
        if(start_loc == (uintptr_t)-1) {
            std::stringstream msg;
            msg << "Could not find location for " << curr_func.first;
            throw std::runtime_error(msg.str());
        }

        do {
            count = cs_disasm(handle_, (uint8_t *)curr_loc, curr_func.second - (curr_loc - start_loc), curr_loc, 1, &insn);
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

                if (std::strcmp(insn->mnemonic, "jmp") == 0) {
                    uintptr_t loc;
                    std::stringstream addr_str;
                    addr_str << std::hex << insn->op_str;
                    addr_str >> loc;

                    std::pair<std::string, size_t> sym = find_closest_sym(loc);
                    if(visited.find(sym) == visited.end()) {
                        jmp_tgts.push_back(sym);
                        curr_loc = loc;
                        curr_func = sym;
                        start_loc = binDesc_.getSymLocation(curr_func);
                        if(start_loc == (uintptr_t)-1) {
                            std::stringstream msg;
                            msg << "Could not find location for " << curr_func.first;
                            throw std::runtime_error(msg.str());
                        }
                    } else {
                        curr_loc = insn->address + insn->size;
                    }
                } else {
                    curr_loc = insn->address + insn->size;
                }
            }
            cs_free(insn, count);
        } while (count > 0);

        jmp_tgts.pop_back();
    }

    arg_count_ = regs_used_in_args.size();

    return fbf::ITestCase::PASS;
}

std::pair<std::string, size_t> fbf::ArgumentCountTestCase::find_closest_sym(uintptr_t location) {
    uintptr_t curr_loc = location;
    std::pair<std::string, size_t> test = binDesc_.getSym(curr_loc);
    while(test.second == 0 && curr_loc > 0) {
        test = binDesc_.getSym(--curr_loc);
    }

    if(curr_loc == 0) {
        std::stringstream msg;
        msg << "No symbol located at location 0x" << std::hex << location;
        throw std::runtime_error(msg.str());
    }

    return test;
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
