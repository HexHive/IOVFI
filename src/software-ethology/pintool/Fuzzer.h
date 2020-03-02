//
// Created by derrick on 3/2/20.
//

#ifndef FOSBIN_FUZZER_H
#define FOSBIN_FUZZER_H

namespace fuzzer {
    class Fuzzer {
    public:
        Fuzzer(MutationDispatcher &MD);

        ~Fuzzer();
    };
}


#endif //FOSBIN_FUZZER_H
