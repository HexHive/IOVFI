//
// Created by derrick on 12/31/18.
//

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        exit(1);
    }

    void *sym = dlopen(argv[1], RTLD_NOW);
    if (sym == NULL) {
        fprintf(stderr, "ERROR Opening %s: %s", argv[1], dlerror());
    }
    return 0;
}