//
// Created by derrick on 7/21/18.
//

#include <stdio.h>
#include "fosbin_test.h"

/* This test relies on the knowledge that the format string is
 * going to be "%d %d". An actual test of sprintf would be
 * variadic. C'est la vie.
 */
FOSBIN_TEST
int sprintf_test(char* dest, const char* fmt, int arg1, int arg2) {
    return sprintf(dest, fmt, arg1, arg2);
}

int main(int argc, char* argv) {
    char buf[128];
    sprintf_test(buf, "%d %d", 1, 1);
    return printf("%s", buf);
}
