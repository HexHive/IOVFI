//
// Created by derrick on 12/4/18.
//
#include "pin.H"
#include <iostream>

int main(int argc, char** argv) {
    if(PIN_Init(argc, argv)) {
        std::cout << "PIN_Init failed" << std::endl;
    } else {
        std::cout << "PIN_Init succeeded" << std::endl;
    }

    return 0;
}
