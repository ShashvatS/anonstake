use std::env;
use std::path::Path;
use std::fs::create_dir;
use crate::config::{RunConfig, RunMode};
use crate::constants::binomial_constants::TauValue;
use crate::constants::binomial_constants::TauValue::{Tau20, Tau1500, Tau2990, Tau5000};

pub enum CLIError {
    DirectoryCreationFailure
}


pub fn get_run_config<'a>() -> Result<Vec<RunConfig<'a>>, CLIError> {
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

    let gen_params = learn_params_gen()?;
    if gen_params.len() != 0 {
        return Ok(gen_params);
    }

    return Ok(vec![]);
}


pub fn learn_params_gen<'a>() -> Result<Vec<RunConfig<'a>>, CLIError> {
    println!("{}", Path::new("./prover_params").exists());

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
                let is_bp = (i == 0);

                let merkle_height = match use_poseidon {
                    true => 10,
                    false => 29
                };

                configs.push(RunConfig {
                    tau,
                    is_bp,
                    merkle_height,
                    test_constraint_system: true,
                    create_params: true,
                    params_out_file: "",
                    params_in_file: "",
                    check_params: false,
                    mode: RunMode::OnlyGenParams,
                    use_poseidon,
                    file_loc: path
                });
            }
        }
    }

    println!("\nAfter the parameters have been generated, re-run this program\n\n");
    Ok(configs)
}