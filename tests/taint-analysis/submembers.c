//
// Created by derrick on 12/22/18.
//

#include <stdio.h>
#include <stdlib.h>

struct A {
    int i;
    char *s;
};

struct B {
    int i;
    struct A a;
};

struct C {
    int i;
    struct B *b;
    struct C *c;
};

void printA(struct A *a) {
    if (a->i > 0) {
        printf("i > 0");
    } else {
        printf("i <= 0");
    }

    printf("%s", a->s);
    a->i++;
}

int main(int argc, char **argv) {
    struct A a;
    a.i = rand();
    a.s = argv[0];
    printA(&a);
    return 0;
}