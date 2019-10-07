//
// Created by shashvat on 10/6/19.
//

#include "experimentation.h"

#include <iostream>
#include <libfqfft/evaluation_domain/get_evaluation_domain.hpp>
#include <omp.h>

#include "FR.h"

int some_tests() {
    auto domain = libfqfft::get_evaluation_domain<FieldR>(1 << 17);

    std::vector<FieldR> test[24];
    for (int j = 0; j < 24; ++j) {
        test[j] = std::vector<FieldR>(1 << 17);
        for (int i = 0; i < test[j].size(); ++i) {
            test[j][i] = FieldR::random_element();
        }
    }

    auto start = omp_get_wtime();
#pragma omp parallel for num_threads(12)
    for (int j = 0; j < 24; ++j) {
        domain->FFT(test[j]);
    }
    auto end = omp_get_wtime();

    auto time = end - start;
    std::cout << time << '\n';
}
