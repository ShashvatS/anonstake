use crate::constants::binomial_constants::TauValue;

#[derive(Clone)]
pub(crate) enum RunMode {
    Single,
    SingleBatch,
    DoubleBatch,
    OnlyGenParams
}

#[derive(Clone)]
pub(crate) struct RunConfig<'a> {
    pub(crate) tau: TauValue,
    pub(crate) is_bp: bool,
    pub(crate) merkle_height: usize,
    pub(crate) test_constraint_system: bool,
    pub(crate) create_params: bool,
    pub(crate) params_out_file: &'a str,
    pub(crate) params_in_file: &'a str,
    pub(crate) check_params: bool,
    pub(crate) mode: RunMode,
    pub(crate) use_poseidon: bool
}

impl RunConfig<'_> {
    pub fn config1() -> RunConfig<'static> {
        RunConfig {
            tau: TauValue::Tau1500,
            is_bp: true,
            merkle_height: 10,
            test_constraint_system: true,
            create_params: false,
            params_out_file: "./output/params_tau1500_bp",
            params_in_file: "./output/params_tau1500_bp",
            check_params: false,
            mode: RunMode::Single,
            use_poseidon: true
        }
    }

    pub fn config2() -> RunConfig<'static> {
        RunConfig {
            tau: TauValue::Tau1500,
            is_bp: true,
            merkle_height: 10,
            test_constraint_system: true,
            create_params: true,
            params_out_file: "./output/debug_params_tau1500_bp",
            params_in_file: "./output/debug_params_tau1500_bp",
            check_params: false,
            mode: RunMode::Single,
            use_poseidon: true
        }
    }

    pub fn config3() -> RunConfig<'static> {
        RunConfig {
            tau: TauValue::Tau1500,
            is_bp: true,
            merkle_height: 10,
            test_constraint_system: true,
            create_params: false,
            params_out_file: "./output/debug_params_tau1500_bp",
            params_in_file: "./output/debug_params_tau1500_bp",
            check_params: false,
            mode: RunMode::SingleBatch,
            use_poseidon: true
        }
    }

    pub fn config4() -> RunConfig<'static> {
        RunConfig {
            tau: TauValue::Tau1500,
            is_bp: true,
            merkle_height: 10,
            test_constraint_system: true,
            create_params: false,
            params_out_file: "./output/debug_params_tau1500_bp",
            params_in_file: "./output/debug_params_tau1500_bp",
            check_params: false,
            mode: RunMode::DoubleBatch,
            use_poseidon: true
        }
    }
}

