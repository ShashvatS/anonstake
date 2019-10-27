//
// Created by shashvat on 10/6/19.
//

#include "FR.h"

const bigint_r prime_r("52435875175126190479447740508185965837690552500527"
                 "637822603658699938581184513");

void initFieldR() {
    assert(FieldR::modulus_is_valid());

    FieldR::Rsquared = bigint_r("3294906474794265442129797520630710739278575682"
                                "199800681788903916070560242797");
    FieldR::Rcubed = bigint_r("498292539885403193545507422492760844601274463553"
                              "15915089527227471280320770991");
    FieldR::inv = 0xfffffffeffffffff;
    //             0x7fffffff

    FieldR::num_bits = 255;
    FieldR::euler = bigint_r("2621793758756309523972387025409298291884527625026"
                             "3818911301829349969290592256");
    FieldR::s = 32;
    FieldR::t = bigint_r(
            "12208678567578594777604504606729831043093128246378069236549469339647");

    FieldR::t_minus_1_over_2 = bigint_r(
            "6104339283789297388802252303364915521546564123189034618274734669823");
    FieldR::multiplicative_generator = FieldR("7");
    FieldR::root_of_unity = FieldR("1023822735773949582365103057584923206255886"
                                   "0180284477541189508159991286009131");
    FieldR::nqr = FieldR("7");
    FieldR::nqr_to_t = FieldR("102382273577394958236510305758492320625588601802"
                              "84477541189508159991286009131");
}

void checkFieldR() {
    std::cout << "Checking FieldR valid (not complete check)" << std::endl;
    assert(FieldR::modulus_is_valid());

    {
        FieldR R = FieldR(FieldR::Rsquared).sqrt();
        FieldR Rcubed = FieldR(FieldR::Rcubed);

        assert(R * R * R == Rcubed || R * R * R == -Rcubed);
    }

    {
        FieldR maybeeuler = (FieldR(0) - FieldR(1)) * FieldR(2).inverse();
        assert(maybeeuler.as_bigint() ==
               FieldR::euler);
    }

    {
        FieldR tmp(1);
        for (int i = 0; i < FieldR::s; ++i) {
            tmp *= 2;
        }
        assert(tmp * FieldR(FieldR::t) + FieldR(1) == FieldR(0));

        FieldR t_minus1_over2 = (FieldR(FieldR::t) - FieldR(1))*(FieldR(2).inverse());
        assert(t_minus1_over2.as_bigint() == FieldR::t_minus_1_over_2);

        assert((FieldR::root_of_unity ^ tmp.as_bigint()) == FieldR(1).as_bigint());
    }

    assert((FieldR::nqr ^ FieldR::t) == FieldR::nqr_to_t);
}
