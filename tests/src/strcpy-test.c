//
// Created by derrick on 7/18/18.
//

#include <stddef.h>

#include "fosbin_test.h"

FOSBIN_TEST
char* strcpy_test(char* dest, const char* src) {
    size_t i;
    for(i = 0; src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
    return dest;
}

int main() {
    char dest[10];
    char* src = "test";
    strcpy_test(dest, src);
    return 0;
}