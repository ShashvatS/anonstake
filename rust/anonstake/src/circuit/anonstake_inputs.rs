use zcash_primitives::jubjub::JubjubEngine;
use zcash_primitives::pedersen_hash::{pedersen_hash, Personalization};
use crate::constants::Constants;
use crate::circuit::AnonStake;
use rand::{thread_rng, Rng};
use ff::{Field, PrimeField, PrimeFieldRepr};

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
//    pub a_pk: Option<E::Fr>,
    pub value: Option<u64>,
    pub rho: Option<E::Fr>,
    pub s: Option<E::Fs>,
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
//                    a_pk: None,
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
//                    a_pk: Some(E::Fr::random(rng)),
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

    pub fn init_testing(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize, j_i: u64) -> AnonStake<'a, E> {
        let rng = &mut thread_rng();

        let mut cm_merkle_path = vec![];
        let mut sn_merkle_path = vec![];
        for _i in 0..merkle_height {
            let val = (E::Fr::random(rng), rng.gen());
            cm_merkle_path.push(Some(val));
            let val = (E::Fr::random(rng), rng.gen());
            sn_merkle_path.push(Some(val));
        }

        let (rho, a_sk, sn_less, sn_plus) = {
            let rho: E::Fr = E::Fr::random(rng);
            let a_sk: E::Fr = E::Fr::random(rng);

            let sn: E::Fr = {
                let all_bits: Vec<bool> = {
                    let mut all_bits = vec![];
                    let mut rho = rho.into_repr();
                    let mut a_sk = a_sk.into_repr();

                    for _ in 0..E::Fr::NUM_BITS {
                        all_bits.push(rho.is_odd());
                        rho.div2();
                    }

                    for _ in 0..E::Fr::NUM_BITS {
                        all_bits.push(a_sk.is_odd());
                        a_sk.div2();
                    }

                    all_bits
                };

                let result = pedersen_hash::<E, _>(Personalization::NoteCommitment, all_bits, constants.jubjub);
                result.to_xy().0
            };

            let mut sn_less = sn.clone();
            sn_less.sub_assign(&E::Fr::one());
            let mut sn_plus = sn.clone();
            sn_plus.add_assign(&E::Fr::one());

            (Some(rho), Some(a_sk), Some(sn_less), Some(sn_plus))
        };


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
                    value: Some(2u64.pow(59)),
                    rho,
                    s: Some(E::Fs::random(rng)),
                },
                a_sk,
                sn_less,
                sn_plus,
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
