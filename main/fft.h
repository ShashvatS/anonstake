//
// Created by shashvat on 10/6/19.
//

#ifndef ANONSTAKE_FFT_H
#define ANONSTAKE_FFT_H

#include <libfqfft/evaluation_domain/evaluation_domain.hpp>
#include <memory>
#include <omp.h>
#include <libfqfft/evaluation_domain/get_evaluation_domain.hpp>

template<typename FieldT>
using FFTdomain = std::shared_ptr<libfqfft::evaluation_domain<FieldT>>;

template<typename FieldT>
void singleProof(std::vector<FieldT> poly[3], FFTdomain<FieldT> domain) {
    for (int i = 0; i < 3; ++i) {
        domain->iFFT(poly[i]);
        domain->cosetFFT(poly[i], FieldT::multiplicative_generator);
    }

    for (int i = 0; i < poly[0].size(); ++i) {
        poly[0][i] = poly[0][i] * poly[1][i] - poly[2][i];
    }

    domain->divide_by_Z_on_coset(poly[0]);
    domain->icosetFFT(poly[0], FieldT::multiplicative_generator);
}

template<typename FieldT>
void benchmarkFFT(int numProofs, int size) {
    auto *poly = new std::vector<FieldT>[3 * numProofs];
    for (int i = 0; i < 3 * numProofs; ++i) {
        poly[i].resize(size);
        for (int j = 0; j < size; ++j) {
            poly[i][j] = FieldT::random_element();
        }
    }

    auto domain = libfqfft::get_evaluation_domain<FieldT>(size);

    double start = omp_get_wtime();
#pragma omp parallel for
    for (int i = 0; i < numProofs; ++i) {
        singleProof(poly + 3 * i, domain);
    }
    double end = omp_get_wtime();

    std::cout << (end - start) << '\n';
    delete[] poly;
}

#endif //ANONSTAKE_FFT_H
