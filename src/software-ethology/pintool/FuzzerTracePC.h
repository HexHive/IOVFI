//
// Created by derrick on 3/2/20.
//

#ifndef FOSBIN_FUZZERTRACEPC_H
#define FOSBIN_FUZZERTRACEPC_H

#include "pin.H"

namespace fuzzer {
    class TracePC {
    public:
        static const size_t kNumPCs = 1 << 21;
        // How many bits of PC are used from __sanitizer_cov_trace_pc.
        static const size_t kTracePcBits = 18;

    private:
        uint8_t *Counters() const;

        uintptr_t *PCs() const;
    };

    void __sanitizer_cov_trace_pc(uintptr_t PC);
}

#endif //FOSBIN_FUZZERTRACEPC_H
