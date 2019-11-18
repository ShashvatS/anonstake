use std::env;
use std::fs::create_dir;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use num_cpus;

use bellman::multicore::implementation;

use crate::constants::binomial_constants::TauValue::{Tau1500, Tau20, Tau2000, Tau2990, Tau5000};
use crate::constants::binomial_constants::TauValue;
use clap::{App, ArgMatches};

pub enum CLIError {
    DirectoryCreationFailure,
    CannotAccessCWD,
}

#[derive(Clone)]
pub enum RunMode {
    OnlyGenParams(PathBuf),
    Sample(PathBuf),
    Single(PathBuf, PathBuf, u32),
    Batch(PathBuf, PathBuf, u32, u32),
}

#[derive(Clone)]
pub struct RunConfig {
    pub tau: TauValue,
    pub is_bp: bool,
    pub merkle_height: usize,
    pub test_constraint_system: bool,
    pub check_params: bool,
    pub mode: RunMode,
    pub use_poseidon: bool,
}

pub fn get_run_config() -> Result<Vec<RunConfig>, CLIError> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    if !Path::new("./prover_params").exists() {
        match create_dir(&Path::new("./prover_params")) {
            Err(e) => {
                println!("{}", e.to_string());
                println!("Error in creating directory ./prover_params");
                println!("Please try running this program again");
                return Err(CLIError::DirectoryCreationFailure);
            }
            Ok(_) => {
                println!("Created directory ./prover_params\n");
            }
        }
    }

    if !Path::new("./benchmarks").exists() {
        match create_dir(&Path::new("./benchmarks")) {
            Err(e) => {
                println!("{}", e.to_string());
                println!("Error in creating directory ./benchmarks");
                println!("Please try running this program again");
                return Err(CLIError::DirectoryCreationFailure);
            }
            Ok(_) => {
                println!("Created directory ./benchmarks\n");
            }
        }
    }

    if let Some(_) = matches.subcommand_matches("gen_params") {
        return get_params_gen();
    } else {
        let gen_params = get_params_gen()?;
        if gen_params.len() != 0 {
            return Ok(gen_params);
        }
    }

    if let Some(_) = matches.subcommand_matches("test") {
        return sample_all_proofs();
    }

    read_command_line_params(matches)
}

pub fn get_params_gen() -> Result<Vec<RunConfig>, CLIError> {
    let tau_vals = [Tau20, Tau1500, Tau2990, Tau5000];
    let is_bp = ["_block_proposer", "", "", ""];

    let mut configs = vec![];

    let mut all_exist = true;
    for i in 0..4 {
        for use_poseidon in vec![true, false] {
            let param = {
                let tau: &str = (&tau_vals[i]).into();
                let bp = &is_bp[i];
                let up = if use_poseidon { "" } else { "_no_poseidon" };
                format!("{}{}{}", tau, bp, up)
            };

            let path = {
                let path = env::current_dir();
                match path {
                    Err(_) => return Err(CLIError::CannotAccessCWD),
                    Ok(mut path) => {
                        path.push(format!("prover_params/{}.params", &param));
                        path
                    }
                }
            };

            if !path.exists() {
                if all_exist {
                    println!("The following parameters for the following zk-SNARK circuit need to be generated: ");
                    all_exist = false;
                }

                println!("{} ", param);

                let tau = (&tau_vals[i]).clone();
                let is_bp: bool = i == 0;

                let merkle_height = if use_poseidon { 10 } else { 29 };

                configs.push(RunConfig {
                    tau,
                    is_bp,
                    merkle_height,
                    test_constraint_system: true,
                    check_params: false,
                    mode: RunMode::OnlyGenParams(path),
                    use_poseidon,
                });
            }
        }
    }

    if !all_exist {
        println!("\nAfter the parameters have been generated, re-run this program\n\n");
    }

    Ok(configs)
}

pub fn sample_all_proofs() -> Result<Vec<RunConfig>, CLIError> {
    let tau_vals = [Tau20, Tau1500, Tau2990, Tau5000];
    let is_bp = ["_block_proposer", "", "", ""];

    let mut configs = vec![];

    for i in 0..4 {
        for use_poseidon in vec![true, false] {
            let tau: &str = (&tau_vals[i]).into();
            let bp = &is_bp[i];
            let up = if use_poseidon { "" } else { "_no_poseidon" };

            let path = {
                let param = format!("{}{}{}", tau, bp, up);

                let path = env::current_dir();
                match path {
                    Err(_) => return Err(CLIError::CannotAccessCWD),
                    Ok(mut path) => {
                        path.push(format!("prover_params/{}.params", &param));
                        path
                    }
                }
            };

            let tau = (&tau_vals[i]).clone();
            let is_bp = i == 0;

            let merkle_height = match use_poseidon {
                true => 10,
                false => 29
            };

            configs.push(RunConfig {
                tau,
                is_bp,
                merkle_height,
                test_constraint_system: true,
                check_params: false,
                mode: RunMode::Sample(path),
                use_poseidon,
            });
        }
    }

    Ok(configs)
}

pub fn read_command_line_params(matches: ArgMatches) -> Result<Vec<RunConfig>, CLIError> {
    let is_batch;
    let single_batch;

    if let Some(_) = matches.subcommand_matches("single") {
        single_batch = "single";
        is_batch = false;
    }
    else if let Some(_) = matches.subcommand_matches("batch") {
        single_batch = "batch";
        is_batch = true;
    }
    else {
        return Ok(vec![]);
    }

    if let Some(matches) = matches.subcommand_matches(single_batch) {
        let (tau, is_bp, use_poseidon) = {
            let num: u32 = value_t!(matches, "role", u32).unwrap_or(0) % 8;

            match num {
                0 => (Tau20, true, true),
                1 => (Tau20, true, false),
                2 => (Tau1500, false, true),
                3 => (Tau1500, false, false),
                4 => (Tau2990, false, true),
                5 => (Tau2990, false, false),
                6 => (Tau5000, false, true),
                7 => (Tau5000, false, false),
                _ => (Tau2000, false, false)
            }
        };

        let merkle_height = if use_poseidon { 10 } else { 29 };

        let trials = value_t!(matches, "trials", u32).unwrap_or(5);

        let threads = value_t!(matches, "threads", usize).unwrap_or(num_cpus::get());
        let version = matches.value_of("output").unwrap_or("0");

        implementation::NUM_CPUS.store(threads, Ordering::SeqCst);
        implementation::HAS_LOADED.store(true, Ordering::SeqCst);

        let mode = {
            let param = {
                let tau: &str = (&tau).into();
                let bp = if is_bp { "_block_proposer" } else { "" };
                let up = if use_poseidon { "" } else { "_no_poseidon" };
                format!("{}{}{}", tau, bp, up)
            };

            let (path, output_file) = {
                let path = env::current_dir();
                let path = match path {
                    Err(_) => return Err(CLIError::CannotAccessCWD),
                    Ok(mut path) => {
                        path.push(format!("prover_params/{}.params", &param));
                        path
                    }
                };

                let output_file = env::current_dir();
                let output_file = match output_file {
                    Err(_) => return Err(CLIError::CannotAccessCWD),
                    Ok(mut path) => {
                        path.push(format!("benchmarks/{}_{}_threads_{}_v{}.csv", &param, threads, single_batch, version));
                        path
                    }
                };

                (path, output_file)
            };

            if is_batch {
                let num_batch = value_t!(matches, "num_batch", u32).unwrap_or(24);
                RunMode::Batch(path, output_file, trials, num_batch)
            } else {
                RunMode::Single(path, output_file, trials)
            }

        };

        let config = RunConfig {
            tau,
            is_bp,
            merkle_height: merkle_height,
            test_constraint_system: false,
            check_params: false,
            mode: mode,
            use_poseidon,
        };

        return Ok(vec![config]);
    }
    else {
        return Ok(vec![]);
    }
}
