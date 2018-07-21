//
// Created by derrick on 7/10/18.
//

#include <stddef.h>
#include "fosbin_test.h"

FOSBIN_TEST
void* memcpy_test(void* dest, const void* src, size_t n) {
    char* d = (char*)dest;
    char* s = (char*)src;
    size_t i;

    for(i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}
