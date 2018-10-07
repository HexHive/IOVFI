//
// Created by derrick on 10/7/18.
//

#include <fosbin-sleuth/argumentCountTestCase.h>

#include "fosbin-sleuth/argumentCountTestCase.h"
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include <iostream>

fbf::ArgumentCountTestCase::ArgumentCountTestCase(uintptr_t location, size_t size) :
    ITestCase(), location_(location), size_(size), arg_count_(0), handle_(0) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
        throw std::runtime_error("Could not open capstone handle");
    }
}

fbf::ArgumentCountTestCase::~ArgumentCountTestCase() {
    if(handle_ != 0) {
        cs_close(&handle_);
    }
}

const std::string fbf::ArgumentCountTestCase::get_test_name() {
    std::stringstream ss;
    ss << "Argument Count Test at " << std::hex << location_;
    return ss.str();
}

int fbf::ArgumentCountTestCase::run_test() {
    size_t count;
    cs_insn* insn;
    uint64_t curr_loc = (uint64_t)location_;
    cs_x86* x86;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;
    do {
        count = cs_disasm(handle_, (uint8_t*)curr_loc, size_ - (curr_loc - location_), curr_loc, 1, &insn);
        if(count > 0) {
            curr_loc += insn->address + insn->size;
            if(insn->detail == NULL) {
                cs_free(insn, count);
                continue;
            }

            x86 = &(insn->detail->x86);
            for(int i = 0; i < x86->op_count; i++) {
                cs_x86_op* op = &(x86->operands[i]);
                if(!cs_reg)
            }

            cs_free(insn, count);
        }

    } while(count > 0);
}

uint64_t fbf::ArgumentCountTestCase::get_value() {
    return 0;
}
