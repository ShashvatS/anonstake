//
// Created by shashvat on 10/26/19.
//
#include <iostream>
#include "FR.h"

extern "C" {
    void hello_world() {
        std::cout << "hello, world!" << std::endl;
    }

    void init() {
        initFieldR();
        checkFieldR();
    }
}


