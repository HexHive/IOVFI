//
// Created by derrick on 10/7/18.
//

#ifndef FOSBIN_ARGUMENTCOUNTTEST_H
#define FOSBIN_ARGUMENTCOUNTTEST_H

#include "iTestCase.h"
#include <capstone/capstone.h>

namespace fbf {
    class ArgumentCountTestCase : public ITestCase {
    public:
        ArgumentCountTestCase(uintptr_t location, size_t size, BinaryDescriptor &binDesc);

        virtual ~ArgumentCountTestCase();

        virtual const std::string get_test_name();

        virtual int run_test();

    protected:
        size_t size_;
        uint8_t arg_count_;
        csh handle_;
        BinaryDescriptor binDesc_;

        bool reg_used_as_arg(uint16_t reg);

        uint16_t get_reg_id(uint16_t reg);

        bool is_floating_reg(uint16_t reg);

        inline constexpr static uint16_t REG_ABI_ORDER[] = {
                X86_REG_RDI,
                X86_REG_RSI,
                X86_REG_RDX,
                X86_REG_RCX,
                X86_REG_R8,
                X86_REG_R9
        };

        inline constexpr static uint16_t FLOAT_REG_ABI_ORDER[] = {
                X86_REG_XMM0,
                X86_REG_XMM1,
                X86_REG_XMM2,
                X86_REG_XMM3,
                X86_REG_XMM4,
                X86_REG_XMM5
        };

        inline constexpr static size_t NUM_ARG_REGS = sizeof(REG_ABI_ORDER) / sizeof(uint16_t);
        const static int32_t INVALID_SYSCALL_VAL = -1;
    };
}


#endif //FOSBIN_ARGUMENTCOUNTTEST_H
