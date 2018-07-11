//
// Created by derrick on 7/10/18.
//

#include <stddef.h>

void* memcpy_test(void* dest, const void* src, size_t n) {
    char* d = (char*)dest;
    char* s = (char*)src;
    size_t i;

    for(i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}

int main(int argc, char** argv) {
    char src[5];
    char dest[5];

    memcpy_test(dest, src, sizeof(dest));
}