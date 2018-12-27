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
        a->i++;
    } else {
        a->i--;
    }

    if (a->s[0] == '\0') {
        a->s++;
    }
}

void printB(struct B *b) {
    if (b->i > 0) {
        b->a.i = b->i;
    } else {
        b->i = b->a.i - 1;
    }

    if (b->a.s[0] == '\0') {
        b->a.s++;
    }
}

void printC(struct C *c) {
    if (c->i > 0) {
        c->i += 2;
    } else {
        c->i += 3;
    }

    if (c->b->i > c->b->a.i) {
        c->i++;
    } else {
        c->i--;
    }

    if (c->c->i > c->b->i) {
        c->i--;
    } else {
        c->i++;
    }
}

void printC2(struct C *c, struct B *b) {
    struct B tmp = *c->b;
    if (tmp.i == b->i) {
        c->i++;
    }
}

int main(int argc, char **argv) {
    struct A a;
    a.i = rand();
    a.s = argv[0];
    printA(&a);
    return 0;
}