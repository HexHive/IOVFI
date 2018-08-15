//
// Created by derrick on 8/15/18.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fosbin_test.h"

/* This test relies on the knowledge that the format string is
 * going to be "%d %d". An actual test of sprintf would be
 * variadic. C'est la vie.
 */
FOSBIN_TEST
void* memmove_test(void* dest, const void* src, size_t n) {
    char* tmp = (char*)malloc(n);
    char* s = (char*)src;
    char* d = (char*)dest;
    for(size_t i = 0; i < n; i++) {
        tmp[i] = s[i];
    }

    for(size_t i = 0; i < n; i++) {
        d[i] = tmp[i];
    }

    free(tmp);

    return dest;
}

int main(int argc, char* argv) {
    char buf0[128];
    char buf1[128];
    memset(buf1, 'A', sizeof(buf1));
    memmove_test(buf0, buf1, sizeof(buf1));
    buf0[127] = '\0';
    return printf("%s", buf0);
}

