use ff::{ScalarEngine};
use zcash_primitives::jubjub::{JubjubEngine};
use crate::constants::mimc_constants::MiMCConstants;

pub mod mimc_constants;
pub mod binomial_constants;

pub struct Constants<'a, E: JubjubEngine>{
    pub mimc: mimc_constants::MiMCConstants<E>,
    pub(crate) jubjub: &'a E::Params,
    pub binomial: binomial_constants::BinomialConstants<E>,
    /* maximum value is actually 2**max_value - 1 */
    pub max_value: usize,
    pub precision: usize
}

impl<'a, E: ScalarEngine + JubjubEngine> Constants<'_, E> {
    pub(crate) fn get(jubjub: &'a E::Params, tau_value: binomial_constants::TauValue) -> Constants<'_, E> {
        Constants {
            mimc: MiMCConstants::get(),
            jubjub: jubjub,
            binomial: tau_value.new(),
            max_value: 60,
            precision: 80
        }
    }

}