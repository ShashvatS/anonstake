use zcash_primitives::jubjub::JubjubEngine;
use crate::constants::Constants;
use crate::circuit::AnonStake;
use rand::{thread_rng, Rng};
use ff::{Field};

pub struct PubInput<E: JubjubEngine> {
//    pub root_cm: Option<E::Fr>,
//    pub root_sn: Option<E::Fr>,
//    pub tsn: Option<E::Fr>,
    pub role: Option<E::Fr>,
    pub seed: Option<E::Fr>,
    pub h: Option<E::Fr>,
//    pub h_sig: Option<E::Fr>
}

pub struct Coin<E: JubjubEngine> {
    pub a_pk: Option<E::Fr>,
    pub value: Option<u64>,
    pub rho: Option<E::Fr>,
    pub s: Option<E::Fs>
}

pub struct AuxInput<E: JubjubEngine> {
    pub cm_merkle_path: Vec<Option<(E::Fr, bool)>>,
    pub sn_merkle_path: Vec<Option<(E::Fr, bool)>>,
    pub coin: Coin<E>,
    pub a_sk: Option<E::Fr>,
    pub sn_less: Option<E::Fr>,
    pub sn_plus: Option<E::Fr>,
    pub j_i: Option<u64>,
}

pub struct BlockProposerPubInput {
    pub r: Option<u64>,
//    pub priority: Option<E::Fr>,
//    pub seed_comp: Option<E::Fr>
}

pub struct BlockProposerAuxInput;


impl<'a, E: JubjubEngine> AnonStake<'_, E> {
    pub fn init_empty(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize) -> AnonStake<'a, E> {
        let mut cm_merkle_path = vec![];
        let mut sn_merkle_path = vec![];
        for _i in 0..merkle_height {
            cm_merkle_path.push(None);
            sn_merkle_path.push(None);
        }

        AnonStake {
            constants: &constants,
            is_bp,
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
                coin: Coin {
                    a_pk: None,
                    value: None,
                    rho: None,
                    s: None,
                },
                a_sk: None,
                sn_less: None,
                sn_plus: None,
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

    pub fn init_pure_random(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize) -> AnonStake<'a, E> {
        let rng = &mut thread_rng();

        let mut cm_merkle_path = vec![];
        let mut sn_merkle_path = vec![];
        for _i in 0..merkle_height {
            let val = (E::Fr::random(rng), rng.gen());
            cm_merkle_path.push(Some(val));
            let val = (E::Fr::random(rng), rng.gen());
            sn_merkle_path.push(Some(val));
        }

        AnonStake {
            constants: &constants,
            is_bp,
            pub_input: PubInput {
//                root_cm: Some(E::Fr::random(rng)),
//                root_sn: Some(E::Fr::random(rng)),
//                tsn: Some(E::Fr::random(rng)),
                role: Some(E::Fr::random(rng)),
                seed: Some(E::Fr::random(rng)),
                h: Some(E::Fr::random(rng)),
//                h_sig: Some(E::Fr::random(rng)),
            },
            aux_input: AuxInput {
                cm_merkle_path,
                sn_merkle_path,
                coin: Coin {
                    a_pk: Some(E::Fr::random(rng)),
                    value: Some(2u64.pow(59)),
                    rho: Some(E::Fr::random(rng)),
                    s: Some(E::Fs::random(rng)),
                },
                a_sk: Some(E::Fr::random(rng)),
                sn_less: Some(E::Fr::random(rng)),
                sn_plus: Some(E::Fr::random(rng)),
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
}
