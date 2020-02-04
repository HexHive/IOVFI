//
// Created by derrick on 1/9/19.
//
#include <iostream>
#include "FBZergContext.h"

void output_context(std::istream &in) {
    if (!in) {
        std::cerr << "istream is not correct!" << std::endl;
        return;
    }

    FBZergContext incontext, outcontext;
    in >> incontext;
    in >> outcontext;

    std::cout << "===============================================" << std::endl;
    std::cout << "                   PreContext                  " << std::endl;
    std::cout << "===============================================" << std::endl;
    incontext.prettyPrint(std::cout);

    std::cout << std::endl;
    std::cout << "===============================================" << std::endl;
    std::cout << "                  PostContext                  " << std::endl;
    std::cout << "===============================================" << std::endl;
    outcontext.prettyPrint(std::cout);
    std::cout << std::endl;
}
