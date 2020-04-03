//
// Created by derrick on 3/2/20.
//

#include "FuzzerTracePC.h"

uintptr_t __sancov_trace_pc_pcs[fuzzer::TracePC::kNumPCs];

uint8_t __sancov_trace_pc_guard_8bit_counters[fuzzer::TracePC::kNumPCs];

namespace fuzzer {
    uint8_t *TracePC::Counters() const {
        return __sancov_trace_pc_guard_8bit_counters;
    }

    uintptr_t *TracePC::PCs() const {
        return __sancov_trace_pc_pcs;
    }

    void __sanitizer_cov_trace_pc(uintptr_t PC) {
        uintptr_t Idx = PC & (((uintptr_t) 1 << fuzzer::TracePC::kTracePcBits) - 1);
        __sancov_trace_pc_pcs[Idx] = PC;
        __sancov_trace_pc_guard_8bit_counters[Idx]++;
    }

}