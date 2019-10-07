use pairing::bls12_381::Bls12;
use crate::circuit::AnonStake;
use zcash_primitives::jubjub::JubjubBls12;

pub mod constants;
pub mod circuit;

fn main() {
    let jubjub = JubjubBls12::new();
    let constants = constants::Constants::<Bls12>::get(&jubjub);

    let anon_stake = AnonStake::<Bls12> {
        constants: &constants
    };

}
