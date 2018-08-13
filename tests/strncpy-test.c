//
// Created by derrick on 8/13/18.
//

#include <stddef.h>

#include "fosbin_test.h"

FOSBIN_TEST
char* strncpy_test(char* dest, const char* src, size_t n) {
    size_t i;
    for(i = 0; src[i] != '\0' && i < n; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
    return dest;
}

int main() {
    char dest[10];
    char* src = "test";
    strncpy_test(dest, src, sizeof(dest));
    return 0;
}
