#[macro_use]
extern crate clap;

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use rand::thread_rng;

use bellman::Circuit;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::groth16::{create_random_proof_with_input,
                       finish_random_proof,
                       generate_random_parameters,
                       Parameters,
                       precompute_proof,
                       prepare_verifying_key,
                       verify_proof};
use pairing::bls12_381::Bls12;
use zcash_primitives::jubjub::JubjubBls12;

use crate::circuit::AnonStake;
use crate::cli::{get_run_config, RunConfig, RunMode};
use crate::constants::Constants;

pub mod constants;
pub mod circuit;
pub mod cli;
pub mod poseidon;

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
            println!("{}", &params_file.to_str().unwrap());

            let params = {
                let anonstake = AnonStake::<Bls12>::init_empty(&constants, config.is_bp, config.merkle_height, config.use_poseidon);
                generate_random_parameters(anonstake, rng).unwrap()
            };

            let path = Path::new(&params_file);
            let file = File::create(path).unwrap();
            params.write(file).unwrap();

            return;
        }
        RunMode::OutputCircuitInfo => {
            run_notification(&config, &constants);
        }
        RunMode::Sample(params_file) => {
            run_notification(&config, &constants);

            let params = {
                println!("{}", &params_file.to_str().unwrap());
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

            let mut total_time = 0;
            for time in times{
                output_file.write_all(format!("{}\n", time).as_ref()).unwrap();
                total_time += time;
            }

            let avg_time = total_time as f64 / trials as f64;
            output_file.write_all(format!("average proof time: {}\n", avg_time).as_ref()).unwrap();


            let pvk = prepare_verifying_key(&params.vk);
            for (proof, input) in &proofs {
                let result = verify_proof(&pvk, &proof, &input[1..]).unwrap();
                if !result {
                    println!("Some proofs failed to verify...");
                    return;
                }
            }
            println!("All proofs verified");
        },
        RunMode::Batch(params_file, output_file, trials, num_batch) => {
            let trials = *trials as usize;
            let num_batch = *num_batch as usize;

            run_notification(&config, &constants);

            let params = {
                let path = Path::new(params_file.to_str().unwrap());
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
            let mut avg_first_proof_time = 0;
            let mut avg_additional_proof_time: u128 = 0;

            for trial_times in times {
                output_file.write_all(format!("{}\n", trial_times.0).as_ref()).unwrap();
                avg_first_proof_time += trial_times.0;
                avg_first_proof_time += trial_times.1[0];


                for (i, time) in trial_times.1.iter().enumerate() {
                    if i != 0 {
                        avg_additional_proof_time += *time;
                    }

                    let end = if i == (trial_times.1.len() - 1) {"\n"} else {", "};
                    output_file.write_all(format!("{}{}", time, end).as_ref()).unwrap();
                }
            }

            let avg_first_proof_time = avg_first_proof_time as f64 / trials as f64;
            output_file.write_all(format!("first proof time: {}\n", avg_first_proof_time).as_ref()).unwrap();
            let avg_additional_proof_time = avg_additional_proof_time as f64 / ((num_batch - 1) as f64 * (trials) as f64);
            output_file.write_all(format!("additional proof time: {}", avg_additional_proof_time).as_ref()).unwrap();

            let pvk = prepare_verifying_key(&params.vk);
            for (proof, input) in &proofs {
                let result = verify_proof(&pvk, &proof, &input[1..]).unwrap();
                if !result {
                    println!("Some proofs failed to verify...");
                    return;
                }
            }
            println!("All proofs verified");
        }
    }
}

fn main() {
    if let Ok(config) = get_run_config() {
        for c in config {
            run(c.clone());
        }
    } else {
        println!("Error in reading input...");
        return;
    }
}
