use pairing::bls12_381::{Bls12};
use crate::circuit::AnonStake;
use zcash_primitives::jubjub::JubjubBls12;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use rand::thread_rng;
use bellman::groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof};
use ff::{Field, ScalarEngine};

pub mod constants;
pub mod circuit;


fn main() {
    let rng = &mut thread_rng();

    let jubjub = JubjubBls12::new();
    let constants = constants::Constants::<Bls12>::get(&jubjub);

    {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let anonstake = AnonStake::<Bls12>::init_pure_random(&constants, true, 29);
        anonstake.synthesize(&mut cs).unwrap();

        println!("{} {}", cs.num_constraints(), cs.num_inputs());
    }

    // Create parameters for our circuit
    let params = {
        let anonstake = AnonStake::<Bls12>::init_empty(&constants, true, 29);
        generate_random_parameters(anonstake, rng).unwrap()
    };

    let proof = {
        let anonstake = AnonStake::<Bls12>::init_pure_random(&constants, true, 29);
        create_random_proof(anonstake, &params, rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    //let result = verify_proof(&pvk, &proof, &[]).unwrap();
    let result = verify_proof(&pvk, &proof, &[<Bls12 as ScalarEngine>::Fr::random(rng)]).unwrap();
    println!("verification result: {} (should be false)", result);
}
