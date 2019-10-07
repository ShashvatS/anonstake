use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, Proof, verify_proof,
};

use ff::{Field, ScalarEngine};
use pairing::bls12_381::Bls12;

use zcash_primitives::jubjub::{JubjubEngine};

use rand::thread_rng;

pub struct AnonStake<'a, E: JubjubEngine> {
    pub constants: &'a crate::constants::Constants<'a, E>
}

impl<'a, E: JubjubEngine> Circuit<E> for AnonStake<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        unimplemented!()
    }
}