//
// Created by shashvat on 10/6/19.
//

#ifndef ANONSTAKE_FR_H
#define ANONSTAKE_FR_H

#include <libff/algebra/fields/bigint.hpp>
#include <libff/algebra/fields/fp.hpp>

typedef libff::bigint<4> bigint_r;
extern const bigint_r prime_r;

//bigint_r prime_r("52435875175126190479447740508185965837690552500527"
//                 "637822603658699938581184513");
typedef libff::Fp_model<4, prime_r> FieldR;

/* parameters for scalar field Fr */
void initFieldR();

void checkFieldR();

#endif //ANONSTAKE_FR_H
