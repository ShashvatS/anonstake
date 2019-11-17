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
use crate::cli::get_run_config;
use crate::constants::Constants;
use std::io::Write;

fn run_notification(config: &RunConfig, constants: &Constants<Bls12>) {
    let param = {
        let tau: &str = (&config.tau).into();
        let bp = match config.is_bp {
            true => "_block_proposer",
            false => ""
        };
        let pos = match config.use_poseidon {
            true => "",
            false => "_no_poseidon"
        };

        format!("{}{}{}", tau, bp, pos)
    };
    print!("params: {} | ", param);

    if config.test_constraint_system {
        print!("params: {} | ", param);

        let mut cs = TestConstraintSystem::<Bls12>::new();
        let anonstake = AnonStake::<Bls12>::init_pure_random(&constants, config.is_bp, config.merkle_height, config.use_poseidon);
        anonstake.synthesize(&mut cs).unwrap();

        println!("constraints: {}, inputs: {}, aux: {}", cs.num_constraints(), cs.num_inputs(), cs.num_aux());
    } else {
        println!("params: {}", param);
    }
}

fn run(config: RunConfig) {
    let rng = &mut thread_rng();
    let jubjub = JubjubBls12::new();
    let constants = constants::Constants::<Bls12>::get(&jubjub, config.tau.clone());

    match &config.mode {
        RunMode::OnlyGenParams(params_file) => {
            run_notification(&config, &constants);
            println!("{}", &params_file);

            let params = {
                let anonstake = AnonStake::<Bls12>::init_empty(&constants, config.is_bp, config.merkle_height, config.use_poseidon);
                generate_random_parameters(anonstake, rng).unwrap()
            };

            let path = Path::new(&params_file);
            let file = File::create(path).unwrap();
            params.write(file).unwrap();

            return;
        }
        RunMode::Sample(params_file) => {
            run_notification(&config, &constants);

            let params = {
                println!("{}", &params_file);
                let path = Path::new(&params_file);
                let file = File::open(path).unwrap();
                Parameters::<Bls12>::read(file, config.check_params).unwrap()
            };

            let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);
            let (proof, input) = create_random_proof_with_input(anonstake, &params, rng).unwrap();

            let pvk = prepare_verifying_key(&params.vk);

            let result = verify_proof(&pvk, &proof, &input[1..]).unwrap();
            println!("verification result: {} (should be true)", result);

            return;
        }
        RunMode::Single(params_file, output_file, trials) => {
            let trials = *trials as usize;
            run_notification(&config, &constants);

            let params = {
                println!("{}", &params_file);
                let path = Path::new(&params_file);
                let file = File::open(path).unwrap();
                Parameters::<Bls12>::read(file, config.check_params).unwrap()
            };

            let mut proofs = Vec::with_capacity(trials);
            let mut times = Vec::with_capacity(trials);

            for _ in 0..trials {
                let start = Instant::now();
                let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);
                let (proof, input) = create_random_proof_with_input(anonstake, &params, rng).unwrap();

                times.push(start.elapsed().as_millis());
                proofs.push((proof, input));
            }

            let mut output_file = File::create(output_file).unwrap();

            for time in times{
                output_file.write_all(format!("{}\n", time).as_ref()).unwrap();
            }
        },
        RunMode::Batch(params_file, output_file, trials, num_batch) => {
            let trials = *trials as usize;
            let num_batch = *num_batch as usize;

            run_notification(&config, &constants);

            let params = {
                println!("{}", &params_file);
                let path = Path::new(&params_file);
                let file = File::open(path).unwrap();
                Parameters::<Bls12>::read(file, config.check_params).unwrap()
            };

            let mut times = Vec::with_capacity(trials);
            let mut proofs = Vec::with_capacity(trials);

            for _ in 0..trials {
                let start = Instant::now();
                let mut iter = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon).into_iter();
                let proof_kernel = precompute_proof(iter.get_copy().unwrap(), &params).unwrap();
                let precomputation_time = start.elapsed().as_millis();

                let mut batch_times = Vec::with_capacity(num_batch);

                for _ in 0..num_batch {
                    let start = Instant::now();
                    let (proof, input) = finish_random_proof(iter.next().unwrap(), &params, rng, &proof_kernel).unwrap();

                    batch_times.push(start.elapsed().as_millis());
                    proofs.push((proof, input));
                }

                times.push((precomputation_time, batch_times));
            }

            let mut output_file = File::create(output_file).unwrap();
            for trial_times in times {
                output_file.write_all(format!("{}\n", trial_times.0).as_ref()).unwrap();

                for (i, time) in trial_times.1.iter().enumerate() {
                    let end = if i == (trial_times.1.len() - 1) {"\n"} else {", "};
                    output_file.write_all(format!("{}{}", time, end).as_ref()).unwrap();
                }
            }

        }
    }


//    else {
//        if config.test_constraint_system {
//            let mut cs = TestConstraintSystem::<Bls12>::new();
//            let anonstake = AnonStake::<Bls12>::init_pure_random(&constants, true, config.merkle_height, config.use_poseidon);
//            anonstake.synthesize(&mut cs).unwrap();
//
//            println!("{} {}", cs.num_constraints(), cs.num_inputs());
//        }
//        if config.create_params {
//            let params = {
//                let anonstake = AnonStake::<Bls12>::init_empty(&constants, true, config.merkle_height, config.use_poseidon);
//                generate_random_parameters(anonstake, rng).unwrap()
//            };
//
//            println!("{}", config.params_out_file);
//
//            let path = Path::new(config.params_out_file);
//            let file = File::create(path).unwrap();
//            params.write(file).unwrap();
//        }
//
//        let params = {
//            let path = Path::new(config.params_in_file);
//            let file = File::open(path).unwrap();
//            Parameters::<Bls12>::read(file, config.check_params).unwrap()
//        };
//
//        let start = Instant::now();
//        let (proof, input) = match config.mode {
//            RunMode::Single => {
//                let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);
//                create_random_proof_with_input(anonstake, &params, rng).unwrap()
//            }
//            RunMode::SingleBatch => {
//                let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);
//
//                let proof_kernel = precompute_proof(anonstake.clone(), &params).unwrap();
//                println!("Precomputation Time: {}", start.elapsed().as_millis());
//
//                let start = Instant::now();
//
//                let res = finish_random_proof(anonstake, &params, rng, &proof_kernel).unwrap();
//                println!("Finish Time (same proof): {}", start.elapsed().as_millis());
//                res
//            }
//            RunMode::DoubleBatch => {
//                let mut iter = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon).into_iter();
//
//                let copy = iter.next().unwrap();
//                let proof_kernel = precompute_proof(copy.clone(), &params).unwrap();
//                println!("Precomputation Time: {}", start.elapsed().as_millis());
//
//                let start = Instant::now();
//                let _res = finish_random_proof(copy, &params, rng, &proof_kernel).unwrap();
//                println!("Finish Time (first proof): {}", start.elapsed().as_millis());
//
//                let start = Instant::now();
//                let res = finish_random_proof(iter.next().unwrap(), &params, rng, &proof_kernel).unwrap();
//                println!("Finish Time (second proof): {}", start.elapsed().as_millis());
//
//                res
//            }
//            _ => {
//                //TODO: implement
//                let anonstake = AnonStake::<Bls12>::init_testing(&constants, config.is_bp, config.merkle_height, 1, config.use_poseidon);
//                create_random_proof_with_input(anonstake, &params, rng).unwrap()
//            }
//        };
//
//        println!("Total Time: {}", start.elapsed().as_millis());
//
//        // Prepare the verification key (for proof verification)
//        let pvk = prepare_verifying_key(&params.vk);
//
//        let result = verify_proof(&pvk, &proof, &input[1..]).unwrap();
//        println!("verification result: {} (should be true)", result);
//    }
}

fn main() {
    unsafe {
        link::hello_world();
        link::init();
    }

    if let Ok(config) = get_run_config() {
        for c in config {
            run(c.clone());
        }
    } else {
        println!("Error in reading input...");
        return;
    }
}
