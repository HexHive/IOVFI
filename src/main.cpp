#include <iostream>
#include <functionIdentifier.h>
#include <fbf-memcpy.h>
#include "fosbin-flop.h"

void *test_memcpy(void *dst, const void *src, size_t nbytes) {
    char *d = (char *) dst;
    char *s = (char *) src;

    for (size_t i = 0; i < nbytes; i++) {
        d[i] = s[i];
    }

    return dst;
}

int main(int argc, char **argv) {
    std::cout << EXE_NAME << " v. " << VERSION_MAJOR << "." << VERSION_MINOR << std::endl;

    fbf::FunctionIdentifier *f = new fbf::MemcpyIdentifier((uintptr_t) &test_memcpy);
    std::cout << "test_memcpy (" << f->get_location() << ")";
    if (f->run_test()) {
        std::cout << " was detected to be memcpy-like!" << std::endl;
    } else {
        std::cout << " was NOT detected to be memcpy-like!" << std::endl;
    }

    delete f;
    return 0;
}