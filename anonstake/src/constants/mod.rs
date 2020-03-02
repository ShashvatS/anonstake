use ff::{ScalarEngine};
use zcash_primitives::jubjub::{JubjubEngine};
use crate::constants::mimc_constants::MiMCConstants;

pub mod mimc_constants;
pub mod binomial_constants;
pub mod poseidon_constants;
pub mod binomial_constants_impl;

pub struct Constants<'a, E: JubjubEngine>{
    pub mimc: mimc_constants::MiMCConstants<E>,
    pub jubjub: &'a E::Params,
    pub binomial: binomial_constants::BinomialConstants<E>,
    pub poseidon: poseidon_constants::PoseidonConstants<E>,
    /* maximum value is actually 2**max_value - 1 */
    pub max_value: usize,
    pub precision: usize
}

impl<'a, E: ScalarEngine + JubjubEngine> Constants<'_, E> {
    pub fn get(jubjub: &'a E::Params, tau_value: binomial_constants::TauValue) -> Constants<'_, E> {
        Constants {
            mimc: MiMCConstants::get(),
            jubjub: jubjub,
            binomial: tau_value.new(),
            poseidon: poseidon_constants::PoseidonConstants::<E>::get(),
            max_value: 60,
            precision: 80
        }
    }

}