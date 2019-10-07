use ff::{ScalarEngine};
use zcash_primitives::jubjub::{JubjubEngine};
use crate::constants::mimc_constants::MiMCConstants;

pub mod mimc_constants;

pub struct Constants<'a, E: JubjubEngine>{
    mimc: mimc_constants::MiMCConstants<E>,
    jubjub: &'a E::Params
}

impl<'a, E: ScalarEngine + JubjubEngine> Constants<'_, E> {
    pub(crate) fn get(jubjub: &'a E::Params) -> Constants<'_, E> {
        Constants {
            mimc: MiMCConstants::get(),
            jubjub: jubjub
        }
    }

}