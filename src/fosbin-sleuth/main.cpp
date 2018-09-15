#include <iostream>
#include "fosbin-sleuth.h"

#include "emptyTestCase.h"

int foo(int a, double b) {
    std::cout << "Foo has been called with a = "
    << a << " and b = " << b << std::endl;
    return 0;
}

int test1() {
    std::cout << "test1 has been called" << std::endl;
    return 0;
}

int main(int argc, char** argv) {
    std::cout << SLEUTH_NAME
        << " v. " << FOSBIN_VERSION_MAJOR << "." << FOSBIN_VERSION_MINOR
        << " starting. Good luck, Sherlock." << std::endl;

    fbf::EmptyTestCase<void> test;
    test.test((uintptr_t)&test1);

    fbf::ArgumentTestCase<void, int, double> test2;
    test2.test((uintptr_t)&foo);

    return 0;
}
