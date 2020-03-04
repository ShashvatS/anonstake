use rand::{Rng, thread_rng};

use ff::Field;
use zcash_primitives::jubjub::{JubjubEngine};

use crate::circuit::AnonStake;
use crate::constants::Constants;

#[derive(Clone)]
pub struct PubInput<E: JubjubEngine> {
    //    pub root_cm: Option<E::Fr>,
//    pub root_sn: Option<E::Fr>,
//    pub tsn: Option<E::Fr>,
//    pub role: Option<E::Fr>,
    pub role: Option<u64>,
    pub seed: Option<E::Fr>,
    pub h: Option<E::Fr>
//    pub h_sig: Option<E::Fr>
}

#[derive(Clone)]
pub struct Coin<E: JubjubEngine> {
    //    pub a_pk: Option<E::Fr>,
    pub value: Option<u64>,
    pub rho: Option<E::Fr>,
    pub s: Option<E::Fs>,
}

#[derive(Clone)]
pub struct AuxInput<E: JubjubEngine> {
    //only used for non-poseidon hash function version
    pub cm_merkle_path: Vec<Option<(E::Fr, bool)>>,
    //only used for non-poseidon hash function version
    pub sn_merkle_path: Vec<Option<(E::Fr, bool)>>,
    pub cm_poseidon_path: Vec<Option<([E::Fr; 8], u8)>>,
    pub sn_poseidon_path: Vec<Option<([E::Fr; 8], u8)>>,
    pub fs_main_tree: [[[Option<E::Fr>; 8]; 3]; 4],
    pub fs_sk: [Option<E::Fs>; 4],
    pub fs_rerandomize_public_key: [Option<E::Fs>; 4],
    pub coin: Coin<E>,
    pub a_sk: Option<E::Fr>,
    pub fs_tree_start: Option<u64>,
    pub sn_less_diff: Option<E::Fr>,
    pub sn_plus_diff: Option<E::Fr>,
    pub j_i: Option<u64>,
}

#[derive(Clone)]
pub struct BlockProposerPubInput {
    pub r: Option<u64>,
//    pub priority: Option<E::Fr>,
//    pub seed_comp: Option<E::Fr>
}

#[derive(Clone)]
pub struct BlockProposerAuxInput;


impl<'a, E: JubjubEngine> AnonStake<'_, E> {
    pub fn init_empty(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize, use_poseidon: bool) -> AnonStake<'a, E> {
        let mut cm_merkle_path = vec![];
        let mut sn_merkle_path = vec![];
        for _i in 0..merkle_height {
            cm_merkle_path.push(None);
            sn_merkle_path.push(None);
        }

        let mut cm_poseidon_path = vec![];
        let mut sn_poseidon_path = vec![];
        for _ in 0..merkle_height {
            cm_poseidon_path.push(None);
            sn_poseidon_path.push(None);
        }

        AnonStake {
            constants: &constants,
            is_bp,
            use_poseidon,
            pub_input: PubInput {
//                root_cm: None,
//                root_sn: None,
//                tsn: None,
                role: None,
                seed: None,
                h: None,
//                h_sig: None,
            },
            aux_input: AuxInput {
                cm_merkle_path,
                sn_merkle_path,
                cm_poseidon_path,
                sn_poseidon_path,
                fs_main_tree: [[[None; 8]; 3]; 4],
                fs_sk: [None; 4],
                fs_rerandomize_public_key: [None; 4],
                coin: Coin {
//                    a_pk: None,
                    value: None,
                    rho: None,
                    s: None,
                },
                a_sk: None,
                fs_tree_start: None,
                sn_less_diff: None,
                sn_plus_diff: None,
                j_i: None,
            },
            bp_pub_input: BlockProposerPubInput {
                r: None,
//                priority: None,
//                seed_comp: None,
            },
            bp_aux_input: BlockProposerAuxInput,
        }
    }

    pub fn init_pure_random(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize, use_poseidon: bool) -> AnonStake<'a, E> {
        let rng = &mut thread_rng();

        let mut cm_merkle_path = vec![];
        let mut sn_merkle_path = vec![];

        for _i in 0..merkle_height {
            let val = (E::Fr::random(rng), rng.gen());
            cm_merkle_path.push(Some(val));
            let val = (E::Fr::random(rng), rng.gen());
            sn_merkle_path.push(Some(val));
        }

        let mut cm_poseidon_path = vec![];
        let mut sn_poseidon_path = vec![];

        for _ in 0..merkle_height {
            let t: u8 = rng.gen::<u8>() % 8;

            let a = [E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng)];
            cm_poseidon_path.push(Some((a, t)));

            let t: u8 = rng.gen::<u8>() % 8;

            let a = [E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng)];
            sn_poseidon_path.push(Some((a, t)));
        }

        let fs_main_tree = {
            let mut fs_main_tree = [[[None; 8]; 3]; 4];
            for i in 0..8 {
                for j in 0..3 {
                    for k in 0..4 {
                        fs_main_tree[k][j][i] = Some(E::Fr::random(rng));
                    }
                }
            }

            fs_main_tree
        };

        AnonStake {
            constants: &constants,
            is_bp,
            use_poseidon,
            pub_input: PubInput {
//                root_cm: Some(E::Fr::random(rng)),
//                root_sn: Some(E::Fr::random(rng)),
//                tsn: Some(E::Fr::random(rng)),
                role: Some(rng.gen()),
                seed: Some(E::Fr::random(rng)),
                h: Some(E::Fr::random(rng)),
//                h_sig: Some(E::Fr::random(rng)),
            },
            aux_input: AuxInput {
                cm_merkle_path,
                sn_merkle_path,
                cm_poseidon_path,
                sn_poseidon_path,
                fs_main_tree,
                fs_sk: [Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng))],
                fs_rerandomize_public_key: [Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng))],
                coin: Coin {
//                    a_pk: Some(E::Fr::random(rng)),
                    value: Some(2u64.pow(59)),
                    rho: Some(E::Fr::random(rng)),
                    s: Some(E::Fs::random(rng)),
                },
                a_sk: Some(E::Fr::random(rng)),
                fs_tree_start: Some(rng.gen()),
                sn_less_diff: Some(E::Fr::random(rng)),
                sn_plus_diff: Some(E::Fr::random(rng)),
                j_i: Some(1),
            },
            bp_pub_input: BlockProposerPubInput {
                r: Some(rng.gen()),
//                priority: Some(E::Fr::random(rng)),
//                seed_comp: Some(E::Fr::random(rng)),
            },
            bp_aux_input: BlockProposerAuxInput,
        }
    }

    pub fn init_testing(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize, j_i: u64, use_poseidon: bool) -> AnonStake<'a, E> {
        let rng = &mut thread_rng();

        let mut cm_merkle_path = vec![];
        let mut sn_merkle_path = vec![];
        for _i in 0..merkle_height {
            let val = (E::Fr::random(rng), rng.gen());
            cm_merkle_path.push(Some(val));
            let val = (E::Fr::random(rng), rng.gen());
            sn_merkle_path.push(Some(val));
        }

        let mut cm_poseidon_path = vec![];
        let mut sn_poseidon_path = vec![];
        for _ in 0..merkle_height {
            let t: u8 = rng.gen::<u8>() % 8;

            let a = [E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng)];
            cm_poseidon_path.push(Some((a, t)));

            let t: u8 = rng.gen::<u8>() % 8;

            let a = [E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng), E::Fr::random(rng)];
            sn_poseidon_path.push(Some((a, t)));
        }

        let fs_main_tree = {
            let mut fs_main_tree = [[[None; 8]; 3]; 4];
            for i in 0..8 {
                for j in 0..3 {
                    for k in 0..4 {
                        fs_main_tree[k][j][i] = Some(E::Fr::random(rng));
                    }
                }
            }

            fs_main_tree
        };

        let role = rng.gen();
        let fs_tree_start = if role < (1 << 36) {
            rng.gen::<u64>() % role
        } else {
            role - (rng.gen::<u64>() % (1 << 36))
        };


        AnonStake {
            constants: &constants,
            is_bp,
            use_poseidon,
            pub_input: PubInput {
//                root_cm: Some(E::Fr::random(rng)),
//                root_sn: Some(E::Fr::random(rng)),
//                tsn: Some(E::Fr::random(rng)),
                role: Some(role),
                seed: Some(E::Fr::random(rng)),
                h: Some(E::Fr::random(rng)),
//                h_sig: Some(E::Fr::random(rng)),
            },
            aux_input: AuxInput {
                cm_merkle_path,
                sn_merkle_path,
                cm_poseidon_path,
                sn_poseidon_path,
                fs_main_tree,
                fs_sk: [Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng))],
                fs_rerandomize_public_key: [Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng)), Some(E::Fs::random(rng))],
                coin: Coin {
                    value: Some(2u64.pow(59)),
                    rho: Some(E::Fr::random(rng)),
                    s: Some(E::Fs::random(rng)),
                },
                a_sk: Some(E::Fr::random(rng)),
                fs_tree_start: Some(fs_tree_start),
                sn_less_diff: Some(E::Fr::one()),
                sn_plus_diff: Some(E::Fr::one()),
                j_i: Some(j_i),
            },
            bp_pub_input: BlockProposerPubInput {
                r: Some(rng.gen()),
//                priority: Some(E::Fr::random(rng)),
//                seed_comp: Some(E::Fr::random(rng)),
            },
            bp_aux_input: BlockProposerAuxInput,
        }
    }
}
