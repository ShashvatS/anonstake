use std::env;
use std::path::Path;
use std::fs::create_dir;
use crate::constants::binomial_constants::TauValue::{Tau20, Tau1500, Tau2990, Tau5000, Tau2000};
use bellman::multicore::implementation;
use std::sync::atomic::Ordering;
use num_cpus;
use crate::constants::binomial_constants::TauValue;

pub enum CLIError {
    DirectoryCreationFailure
}

#[derive(Clone)]
pub enum RunMode {
    OnlyGenParams(String),
    Sample(String),
    Single(String, String, u32),
    Batch(String, String, u32, u32)
}

#[derive(Clone)]
pub struct RunConfig {
    pub tau: TauValue,
    pub is_bp: bool,
    pub merkle_height: usize,
    pub test_constraint_system: bool,
    pub check_params: bool,
    pub mode: RunMode,
    pub use_poseidon: bool
}


pub fn get_run_config() -> Result<Vec<RunConfig>, CLIError> {
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

    let args: Vec<String> = env::args().collect();
    for a in &args {
        print!("{} ", a);
    }
    println!("");

    if args.len() == 1 {
        println!("use --help or -h to print instructions");
        return Ok(vec![]);
    } else if &args[1] == "--help" || &args[1] == "-h" {
        println!("Print instructions here...");
        return Ok(vec![]);
    }

    let gen_params = get_params_gen()?;
    if gen_params.len() != 0 {
        return Ok(gen_params);
    }

    if &args[1] == "--test" || &args[1] == "-t" {
        return Ok(sample_all_proofs());
    }

    read_command_line_params(args)
}

pub fn read_command_line_params(mut args: Vec<String>) -> Result<Vec<RunConfig>, CLIError> {
    let (tau, is_bp, use_poseidon) = {
        let num = &args[1].parse::<u8>();

        let num = match num {
            Ok(n) => n % 8,
            Err(_) => 0
        };

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

    let is_batch = {
        if args.len() <= 2 {
            args.push("single".to_owned());
        }

        &args[2] == "batch"
    };

    let trials = {
        if args.len() <= 3 {
            args.push("5".to_owned());
        }

        let res = &args[3].parse::<u32>();

        match res {
            Ok(a) => a.clone(),
            Err(_) => 5
        }
    };

    let num_batch = {
        if args.len() <= 4 {
            args.push("24".to_owned());
        }

        let res = &args[4].parse::<u32>();

        match res {
            Ok(a) => a.clone(),
            Err(_) => 24
        }
    };

    let cpunum = {
        if args.len() <= 5 {
            args.push("---".to_owned());
        }

        let res = args[5].parse::<usize>();

        match res {
            Ok(a) => a,
            Err(_) => num_cpus::get()
        }
    };

    let version = {
        if args.len() <= 6 {
            args.push("---".to_owned());
        }

        let res = args[6].parse::<usize>();

        match res {
            Ok(a) => a,
            Err(_) => 0
        }
    };

    implementation::NUM_CPUS.store(cpunum, Ordering::SeqCst);
    implementation::HAS_LOADED.store(true, Ordering::SeqCst);

    let mode = {
        let param = {
            let tau: &str = (&tau).into();
            let bp = if is_bp { "_block_proposer" } else { "" };
            let up = if use_poseidon { "" } else { "_no_poseidon" };
            format!("{}{}{}", tau, bp, up)
        };

        let path = format!("./prover_params/{}.params", &param);

        let output_file = format!("./benchmarks/{}_{}_threads_v{}.csv", param, cpunum, version);

        if is_batch {
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
        use_poseidon
    };

    Ok(vec![config])
}

pub fn get_params_gen() -> Result<Vec<RunConfig>, CLIError> {
    let tau_vals = [Tau20, Tau1500, Tau2990, Tau5000];
    let is_bp = ["_block_proposer", "", "", ""];

    let mut configs = vec![];

    let mut all_exist = true;
    for i in 0..4 {
        for use_poseidon in vec![true, false] {
            let tau: &str = (&tau_vals[i]).into();
            let bp = &is_bp[i];
            let up = if use_poseidon { "" } else { "_no_poseidon" };

            let param = format!("{}{}{}", tau, bp, up);
            let path = format!("./prover_params/{}.params", &param);
            let exists = Path::new(&path).exists();

            if !exists {
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
                    use_poseidon
                });
            }
        }
    }

    if !all_exist {
        println!("\nAfter the parameters have been generated, re-run this program\n\n");
    }

    Ok(configs)
}

pub fn sample_all_proofs() -> Vec<RunConfig> {
    let tau_vals = [Tau20, Tau1500, Tau2990, Tau5000];
    let is_bp = ["_block_proposer", "", "", ""];

    let mut configs = vec![];

    for i in 0..4 {
        for use_poseidon in vec![true, false] {
            let tau: &str = (&tau_vals[i]).into();
            let bp = &is_bp[i];
            let up = if use_poseidon { "" } else { "_no_poseidon" };

            let param = format!("{}{}{}", tau, bp, up);
            let path = format!("./prover_params/{}.params", &param);

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
                use_poseidon
            });
        }
    }

    configs
}