//
// Created by shashvat on 10/6/19.
//

#ifndef ANONSTAKE_FFT_H
#define ANONSTAKE_FFT_H

#include <memory>
#include <libfqfft/evaluation_domain/get_evaluation_domain.hpp>

template<typename FieldT>
using FFTdomain = std::shared_ptr<libfqfft::evaluation_domain<FieldT>>;

template<typename FieldT>
void singleProof(std::vector<FieldT> poly[3], FFTdomain<FieldT> domain);

template<typename FieldT>
void benchmarkFFT(int numProofs, int size);

#include "fft.tcc"

#endif //ANONSTAKE_FFT_H
