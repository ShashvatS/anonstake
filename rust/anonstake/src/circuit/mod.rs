use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zcash_primitives::jubjub::JubjubEngine;
use rand::{thread_rng, Rng};
use ff::Field;

pub mod anonstake_inputs;

use anonstake_inputs::*;
use crate::constants::Constants;
use bellman::gadgets::num;
use bellman::gadgets::num::AllocatedNum;

pub mod gadgets;

pub struct AnonStake<'a, E: JubjubEngine> {
    pub constants: &'a crate::constants::Constants<'a, E>,
    pub is_bp: bool,
    pub pub_input: PubInput<E>,
    pub aux_input: AuxInput<E>,
    pub bp_pub_input: BlockProposerPubInput<E>,
    pub bp_aux_input: BlockProposerAuxInput,
}

impl<'a, E: JubjubEngine> AnonStake<'_, E> {
    pub fn init_empty(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize) -> AnonStake<'a, E> {
        let mut cm_merkle_path = vec![];
        for _i in 0..merkle_height {
            cm_merkle_path.push(None);
        }

        AnonStake {
            constants: &constants,
            is_bp,
            pub_input: PubInput {
                root_cm: None,
                root_sn: None,
                tsn: None,
                role: None,
                seed: None,
                h: None,
                h_sig: None,
            },
            aux_input: AuxInput {
                cm_merkle_path,
                coin: Coin {
                    a_pk: None,
                    value: None,
                    rho: None,
                    s: None,
                },
                a_sk: None
            },
            bp_pub_input: BlockProposerPubInput {
                r: None,
                priority: None,
                seed_comp: None,
            },
            bp_aux_input: BlockProposerAuxInput,
        }
    }

    pub fn init_pure_random(constants: &'a Constants<E>, is_bp: bool, merkle_height: usize) -> AnonStake<'a, E> {
        let rng = &mut thread_rng();

        let mut cm_merkle_path = vec![];
        for _i in 0..merkle_height {
            let val = (E::Fr::random(rng), rng.gen());
            cm_merkle_path.push(Some(val));
        }

        AnonStake {
            constants: &constants,
            is_bp,
            pub_input: PubInput {
                root_cm: Some(E::Fr::random(rng)),
                root_sn: Some(E::Fr::random(rng)),
                tsn: Some(E::Fr::random(rng)),
                role: Some(E::Fr::random(rng)),
                seed: Some(E::Fr::random(rng)),
                h: Some(E::Fr::random(rng)),
                h_sig: Some(E::Fr::random(rng)),
            },
            aux_input: AuxInput {
                cm_merkle_path,
                coin: Coin {
                    a_pk: Some(E::Fr::random(rng)),
                    value: Some(rng.gen()),
                    rho: Some(E::Fr::random(rng)),
                    s: Some(E::Fs::random(rng)),
                },
                a_sk: Some(E::Fr::random(rng))
            },
            bp_pub_input: BlockProposerPubInput {
                r: Some(E::Fr::random(rng)),
                priority: Some(E::Fr::random(rng)),
                seed_comp: Some(E::Fr::random(rng))
            },
            bp_aux_input: BlockProposerAuxInput,
        }
    }
}


impl<'a, E: JubjubEngine> Circuit<E> for AnonStake<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

        let a_sk = AllocatedNum::alloc(cs.namespace(|| "allocate a_sk"), || self.aux_input.a_sk.ok_or(SynthesisError::AssignmentMissing))?;

        //kind of hacky but whatever, do not have enough time
        let allocated_zero = AllocatedNum::alloc(cs.namespace(||"allocate fake zero"), || Ok(E::Fr::zero()))?;

        let a_pk = self.mimc_prf(cs.namespace(|| "calc a_pk"), "calc a_pk", a_sk, allocated_zero, &self.constants.mimc.prf_addr)?;

        let (cm, value, rho) = self.constrain_coin_commitment(cs.namespace(|| "coin commitment computation"), "coin commitment computation", a_pk)?;

        self.coin_commitment_membership(cs.namespace(|| "coin commitment membership"), "coin commitment membership", cm)?;
        Ok(())
    }
}