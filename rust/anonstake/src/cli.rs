use std::path::Path;
use std::fs::create_dir;
use crate::config::{RunConfig, RunMode};
use crate::constants::binomial_constants::TauValue;

pub enum CLIError {
    DirectoryCreationFailure
}

pub fn get_run_config() -> Result<(), CLIError> {
    println!("AnonStake Implementation\n");

    if !Path::new("./prover_params").exists() {
        match create_dir(&Path::new("./prover-params")) {
            Err(_) => {
                println!("Error in creating directory ./prover-params");
                println!("Please try running this program again");
                return Err(CLIError::DirectoryCreationFailure);
            },
            Ok(_) => {
                println!("Created directory ./prover-params\n");
            }
        }
    }

    let tau_vals = ["20", "1500", "2990", "5000"];
    let is_bp = ["_block_proposer", "", "", ""];

    let mut configs = vec![];

    let mut all_exist = true;
    for i in 0..4 {
        let param = format!("tau{}{}", tau_vals[i], is_bp[i]);
        let path = format!("./prover_params/{}.params", &param);
        let exists = Path::new(&path).exists();

        if !exists {
            if all_exist {
                println!("The following parameters for the following zk-SNARK circuit need to be generated:");
                all_exist = false;
            }

            println!("{}", param);

            let tau = match i {
                0 => TauValue::Tau20,
                1 => TauValue::Tau1500,
                2 => TauValue::Tau2990,
                3 => TauValue::Tau5000,
                _ => TauValue::Tau2000
            };

            let is_bp = (i == 0);

            let path = match i {
                0 => "./prover_params/tau20_block_proposer.params",
                1 => "./prover_params/tau1500.params",
                _ => "./prover_params/tau2000.params"
            };

            configs.push(RunConfig{
                tau,
                is_bp,
                merkle_height: 10,
                test_constraint_system: true,
                create_params: true,
                params_out_file: "",
                params_in_file: path,
                check_params: false,
                mode: RunMode::Single,
                use_poseidon: true
            });
        }
    }

    println!("After the parameters have been generated, re-run this program");


    Ok(())
}