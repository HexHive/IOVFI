//
// Created by derrick on 7/10/18.
//

#include <stddef.h>
#include "test.h"

FOSTEST
void* memcpy_test(void* dest, const void* src, size_t n) {
    asm("");
    char* d = (char*)dest;
    char* s = (char*)src;
    size_t i;

    for(i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}
