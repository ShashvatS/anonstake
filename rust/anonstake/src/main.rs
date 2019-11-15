use pairing::bls12_381::Bls12;
use crate::circuit::AnonStake;
use zcash_primitives::jubjub::JubjubBls12;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use rand::thread_rng;
use bellman::groth16::{create_random_proof_with_input,
                       precompute_proof,
                       finish_random_proof,
                       generate_random_parameters,
                       prepare_verifying_key,
                       verify_proof,
                       Parameters};
use std::fs::File;
use std::path::Path;
use std::time::Instant;

pub mod constants;
pub mod circuit;
pub mod config;
pub mod link;
pub mod cli;

use config::RunConfig;
use crate::config::RunMode;

fn run(config: RunConfig) {
    let rng = &mut thread_rng();
    let jubjub = JubjubBls12::new();
    let constants = constants::Constants::<Bls12>::get(&jubjub, config.tau);

    if config.test_constraint_system {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let anonstake = AnonStake::<Bls12>::init_pure_random(&constants, true, config.merkle_height, config.use_poseidon);
        anonstake.synthesize(&mut cs).unwrap();

        println!("{} {}", cs.num_constraints(), cs.num_inputs());
    }
    if config.create_params {
        let params = {
            let anonstake = AnonStake::<Bls12>::init_empty(&constants, true, config.merkle_height, config.use_poseidon);
            generate_random_parameters(anonstake, rng).unwrap()
        };

        let path = Path::new(config.params_out_file);
        let file = File::create(path).unwrap();
        params.write(file).unwrap();
    }

    let params = {
        let path = Path::new(config.params_in_file);
        let file = File::open(path).unwrap();
        Parameters::<Bls12>::read(file, config.check_params).unwrap()
    };

    let start = Instant::now();
    let (proof, input) = match config.mode {
        RunMode::Single => {
            let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);
            create_random_proof_with_input(anonstake, &params, rng).unwrap()
        },
        RunMode::SingleBatch => {
            let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);

            let proof_kernel = precompute_proof(anonstake.clone(), &params).unwrap();
            println!("Precomputation Time: {}", start.elapsed().as_millis());

            let start = Instant::now();

            let res = finish_random_proof(anonstake, &params, rng, &proof_kernel).unwrap();
            println!("Finish Time (same proof): {}", start.elapsed().as_millis());
            res
        },
        RunMode::DoubleBatch => {
            let mut iter = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon).into_iter();

            let copy = iter.next().unwrap();
            let proof_kernel = precompute_proof(copy.clone(), &params).unwrap();
            println!("Precomputation Time: {}", start.elapsed().as_millis());

            let start = Instant::now();
            let _res = finish_random_proof(copy, &params, rng, &proof_kernel).unwrap();
            println!("Finish Time (first proof): {}", start.elapsed().as_millis());

            let start = Instant::now();
            let res = finish_random_proof(iter.next().unwrap(), &params, rng, &proof_kernel).unwrap();
            println!("Finish Time (second proof): {}", start.elapsed().as_millis());

            res
        }
        RunMode::OnlyGenParams => {
            //TODO: implement
            let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);
            create_random_proof_with_input(anonstake, &params, rng).unwrap()
        }
    };

    println!("Total Time: {}", start.elapsed().as_millis());

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    let result = verify_proof(&pvk, &proof, &input[1..]).unwrap();
    println!("verification result: {} (should be true)", result);

}

fn main() {
    unsafe {
        link::hello_world();
        link::init();
    }

    let config = RunConfig::config2();
    run(config.clone());
}
