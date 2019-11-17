use crate::constants::binomial_constants::TauValue;

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
//    pub create_params: bool,
//    pub params_out_file: &'a str,
//    pub params_in_file: &'a str,
    pub check_params: bool,
    pub mode: RunMode,
    pub use_poseidon: bool
}

//impl RunConfig<'_> {
//    pub fn config1() -> RunConfig<'static> {
//        RunConfig {
//            tau: TauValue::Tau1500,
//            is_bp: true,
//            merkle_height: 10,
//            test_constraint_system: true,
//            create_params: false,
//            params_out_file: "./output/params_tau1500_bp",
//            params_in_file: "./output/params_tau1500_bp",
//            check_params: false,
//            mode: RunMode::Single,
//            use_poseidon: true,
//            file_loc: "".to_owned(),
//            benchmark_file: "".to_owned()
//        }
//    }
//
//    pub fn config2() -> RunConfig<'static> {
//        RunConfig {
//            tau: TauValue::Tau1500,
//            is_bp: true,
//            merkle_height: 10,
//            test_constraint_system: true,
//            create_params: true,
//            params_out_file: "./output/debug_params_tau1500_bp",
//            params_in_file: "./output/debug_params_tau1500_bp",
//            check_params: false,
//            mode: RunMode::Single,
//            use_poseidon: true,
//            file_loc: "".to_owned(),
//            benchmark_file: "".to_owned()
//        }
//    }
//
//    pub fn config3() -> RunConfig<'static> {
//        RunConfig {
//            tau: TauValue::Tau1500,
//            is_bp: true,
//            merkle_height: 10,
//            test_constraint_system: true,
//            create_params: false,
//            params_out_file: "./output/debug_params_tau1500_bp",
//            params_in_file: "./output/debug_params_tau1500_bp",
//            check_params: false,
//            mode: RunMode::SingleBatch,
//            use_poseidon: true,
//            file_loc: "".to_owned(),
//            benchmark_file: "".to_owned()
//        }
//    }
//
//    pub fn config4() -> RunConfig<'static> {
//        RunConfig {
//            tau: TauValue::Tau1500,
//            is_bp: true,
//            merkle_height: 10,
//            test_constraint_system: true,
//            create_params: false,
//            params_out_file: "./output/debug_params_tau1500_bp",
//            params_in_file: "./output/debug_params_tau1500_bp",
//            check_params: false,
//            mode: RunMode::DoubleBatch,
//            use_poseidon: true,
//            file_loc: "".to_owned(),
//            benchmark_file: "".to_owned()
//        }
//    }
//}
//
