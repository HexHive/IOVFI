#include <iostream>
#include <functionIdentifier.h>
#include <fbf-memcpy.h>
#include "fosbin-flop.h"
#include <identifierFactory.h>
#include <memory>

void *test_memcpy(void *dst, const void *src, size_t nbytes) {
    auto *d = (char *) dst;
    auto *s = (char *) src;

    for (size_t i = 0; i < nbytes; i++) {
        d[i] = s[i];
    }

    return dst;
}

int main(int argc, char **argv) {
    std::cout << EXE_NAME << " v. " << VERSION_MAJOR << "." << VERSION_MINOR << std::endl;

    std::shared_ptr<fbf::FunctionIdentifier> f = fbf::IdentifierFactory
            ::Instance()->CreateIdentifier("memcpy", (uintptr_t) &test_memcpy);
    std::cout << "test_memcpy (" << f->get_location() << ")";
    if (f->run_test()) {
        std::cout << " was detected to be memcpy-like!" << std::endl;
    } else {
        std::cout << " was NOT detected to be memcpy-like!" << std::endl;
    }

    return 0;
}