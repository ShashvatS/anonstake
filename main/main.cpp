//
// Created by shashvat on 10/5/19.
//

//#define MULTICORE

#include "FR.h"
#include "fft.h"

int main() {
    initFieldR();

    benchmarkFFT<FieldR>(12, 1 << 17);
    
    return 0;
}