use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zcash_primitives::jubjub::JubjubEngine;
use ff::{Field, PrimeField};

pub mod anonstake_inputs;

use anonstake_inputs::*;
use bellman::gadgets::num::{AllocatedNum};
use bellman::gadgets::boolean::{Boolean, AllocatedBit};
use bellman::gadgets::{num, boolean};

pub mod gadgets;

#[derive(Clone)]
pub struct AnonStake<'a, E: JubjubEngine> {
    pub constants: &'a crate::constants::Constants<'a, E>,
    pub is_bp: bool,
    pub use_poseidon: bool,
    pub pub_input: PubInput<E>,
    pub aux_input: AuxInput<E>,
    pub bp_pub_input: BlockProposerPubInput,
    pub bp_aux_input: BlockProposerAuxInput,
}

impl<'a, E: JubjubEngine> Circuit<E> for AnonStake<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let a_sk = AllocatedNum::alloc(cs.namespace(|| "allocate a_sk"), || self.aux_input.a_sk.ok_or(SynthesisError::AssignmentMissing))?;

        //kind of hacky but whatever, do not have enough time
        let allocated_zero = AllocatedNum::alloc(cs.namespace(|| "allocate fake zero"), || Ok(E::Fr::zero()))?;

        let a_pk = self.mimc_prf(cs.namespace(|| "calc a_pk"), "calc a_pk", a_sk.clone(), allocated_zero, &self.constants.mimc.prf_addr)?;

        let (cm, _value, value_bits, rho) = self.constrain_coin_commitment(cs.namespace(|| "coin commitment computation"), "coin commitment computation", a_pk)?;

        self.coin_commitment_membership(cs.namespace(|| "coin commitment membership"), "coin commitment membership", cm)?;

        let role = AllocatedNum::alloc(cs.namespace(|| "allocate role"), || self.pub_input.role.ok_or(SynthesisError::AssignmentMissing))?;
        let seed_sel = AllocatedNum::alloc(cs.namespace(|| "allocate seed_sel"), || self.pub_input.seed.ok_or(SynthesisError::AssignmentMissing))?;

        {
            role.inputize(cs.namespace(|| "inputize role"))?;
            seed_sel.inputize(cs.namespace(|| "inputize seed_sel"))?;
        }

        let role_bits = role.to_bits_le_strict(cs.namespace(|| "bits of role"))?;
        let seed_sel_bits = seed_sel.to_bits_le_strict(cs.namespace(|| "bits of seed_sel"))?;

        let hash_role_seed = {
            let mut a = role_bits.clone();
            a.extend(seed_sel_bits.clone());

            self.crh(cs.namespace(|| "hash role seed_sel"), "hash role and seed", a.as_slice())?
        };

        let num_selections = self.calc_num_selections(cs.namespace(|| "calc number selections"), "calc number selections", value_bits.as_slice(), &hash_role_seed, &a_sk)?;

        let j_i_bits = {
            let values = match self.aux_input.j_i {
                Some(ref value) => {
                    let mut tmp = Vec::with_capacity(11);

                    for i in 0..11 {
                        tmp.push(Some(*value >> i & 1 == 1));
                    }

                    tmp
                }
                None => vec![None; 11],
            };

            values
                .into_iter()
                .enumerate()
                .map(|(i, b)| {
                    Ok(Boolean::from(AllocatedBit::alloc(
                        cs.namespace(|| format!("j_i bit {}", i)),
                        b,
                    )?))
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?
        };

        {
            let num_selection_bits = {
                let values = match num_selections.get_value() {
                    Some(value) => {
                        let value = value.into_repr().as_ref()[0];
                        let mut tmp = Vec::with_capacity(11);

                        for i in 0..11 {
                            tmp.push(Some(value >> i & 1 == 1));
                        }

                        tmp
                    }
                    None => vec![None; 11],
                };

                values
                    .into_iter()
                    .enumerate()
                    .map(|(i, b)| {
                        Ok(Boolean::from(AllocatedBit::alloc(
                            cs.namespace(|| format!("num_selection bit {}", i)),
                            b,
                        )?))
                    })
                    .collect::<Result<Vec<_>, SynthesisError>>()?
            };

            let mut num = num::Num::zero();
            let mut coeff = E::Fr::one();
            for bit in &num_selection_bits {
                num = num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }

            cs.enforce(|| "num_selection_bits",
                       |lc| lc + num_selections.get_variable(),
                       |lc| lc + CS::one(),
                       |_| num.lc(E::Fr::one()));


            self.leq_not_fixed(cs.namespace(|| "j_i less than"), "j_i less than", &j_i_bits, &num_selection_bits)?;
        }

        {
            let sn = self.mimc_prf(cs.namespace(|| "calc serial number"), "calc serial number", a_sk.clone(), rho.clone(), &self.constants.mimc.prf_sn)?;

            let sn_less_diff = AllocatedNum::<E>::alloc(cs.namespace(|| "allocate sn_less"), || {
                self.aux_input.sn_less_diff.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let sn_plus_diff = AllocatedNum::<E>::alloc(cs.namespace(|| "allocate sn_plus"), || {
                self.aux_input.sn_plus_diff.ok_or(SynthesisError::AssignmentMissing)
            })?;

            sn_less_diff.assert_nonzero(cs.namespace(|| "assert sn_less_sub nonzero"))?;
            sn_plus_diff.assert_nonzero(cs.namespace(|| "assert sn_plus_sub nonzero"))?;

            //could avoid allocating new numbers but this is so much easier to program
            let sn_less = AllocatedNum::alloc(cs.namespace(|| "assert sn_less_none_zero"), || {
                let mut tmp = sn.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                tmp.sub_assign(&sn_less_diff.get_value().ok_or(SynthesisError::AssignmentMissing)?);
                Ok(tmp)
            })?;

            let sn_plus = AllocatedNum::alloc(cs.namespace(|| "assert sn_plus_none_zero"), || {
                let mut tmp = sn.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                tmp.add_assign(&sn_plus_diff.get_value().ok_or(SynthesisError::AssignmentMissing)?);
                Ok(tmp)
            })?;

            let sn_bits = sn.to_bits_le_strict(cs.namespace(|| "sn bits"))?;
            let sn_less_bits = sn_less.to_bits_le_strict(cs.namespace(|| "sn_less bits"))?;
            let sn_plus_bits = sn_plus.to_bits_le_strict(cs.namespace(|| "sn_plus bits"))?;

            self.leq_not_fixed(cs.namespace(|| "compare sn sn_less"), "compare sn sn_less", &sn_less_bits, &sn_bits)?;

            self.leq_not_fixed(cs.namespace(|| "compare sn sn_plus"), "compare sn sn_plus", &sn_bits, &sn_plus_bits)?;

            let mut all_bits = sn_less_bits;
            all_bits.extend(sn_plus_bits);

            let sn_box = self.crh(cs.namespace(|| "calc sn box"), "calc sn_box", all_bits.as_ref())?;

            self.serial_number_nonmembership(cs.namespace(|| "sn merkle"), "sn merkle", sn_box)?;
        }

        {
            let mut all_bits = rho.to_bits_le(cs.namespace(|| "rho bits"))?;

            all_bits.extend(role_bits.clone());
            all_bits.extend(j_i_bits.clone());

            let hash = self.crh(cs.namespace(|| "prehash calc tsn"), "prehash calc tsn", all_bits.as_ref())?;

            let tsn = self.mimc_prf(cs.namespace(|| "calc tsn"), "calc tsn", a_sk.clone(), hash, &self.constants.mimc.prf_tsn)?;
            tsn.inputize(cs.namespace(|| "inputize tsn"))?;
        }

        let h = AllocatedNum::alloc(cs.namespace(|| "allocate h"), || self.pub_input.h.ok_or(SynthesisError::AssignmentMissing))?;
        h.inputize(cs.namespace(|| "inputize h"))?;

        let _h_sig = self.mimc_prf(cs.namespace(|| "calc h_sig"), "calc h sig", a_sk.clone(), h, &self.constants.mimc.prf_pk)?;

        if self.is_bp {
            let mut all_bits = role_bits.clone();
            all_bits.extend(seed_sel_bits);
            all_bits.extend(j_i_bits.clone());

            let hash = self.crh(cs.namespace(|| "prehash calc priority"), "prehash calc priority", all_bits.as_ref())?;
            let priority = self.mimc_prf(cs.namespace(|| "calc priority"), "calc priority", a_sk.clone(), hash, &self.constants.mimc.prf_priority)?;
            priority.inputize(cs.namespace(|| "inputize priority"))?;

            let round = AllocatedNum::alloc(cs.namespace(|| "allocate round"), || {
                let tmp = self.bp_pub_input.r.ok_or(SynthesisError::AssignmentMissing)?.to_string();
                E::Fr::from_str(&tmp).ok_or(SynthesisError::AssignmentMissing)
            })?;

            round.inputize(cs.namespace(|| "inputize round"))?;

            // Booleanize the value into little-endian bit order
            let round_bits = boolean::u64_into_boolean_vec_le(
                cs.namespace(|| "round bits"),
                self.bp_pub_input.r,
            )?;

            let mut num = num::Num::zero();
            let mut coeff = E::Fr::one();
            for bit in &round_bits {
                num = num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }

            cs.enforce(|| "round bits enforce",
                       |lc| lc + round.get_variable(),
                       |lc| lc + CS::one(),
                       |_| num.lc(E::Fr::one()));

            let mut all_bits = round_bits;
            all_bits.extend(j_i_bits);

            let hash = self.crh(cs.namespace(|| "prehash calc seed_comp"), "prehash calc seed_comp", all_bits.as_ref())?;

            let seed_comp = self.mimc_prf(cs.namespace(|| "calc seed_comp"), "calc seed_comp", a_sk.clone(), hash, &self.constants.mimc.prf_seed)?;
            seed_comp.inputize(cs.namespace(||"inputize seed_comp"))?;
        }

        Ok(())
    }
}

pub struct AnonStakeIterator<'a, E: JubjubEngine> {
    a: AnonStake<'a, E>
}

impl<'a, E: JubjubEngine> Iterator for AnonStakeIterator<'a, E> {
    type Item = AnonStake<'a, E>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.a.clone();

        if let Some(j_i) = self.a.aux_input.j_i {
            self.a.aux_input.j_i = Some(j_i + 1)
        }

        Some(ret)
    }
}

impl<'a, E: JubjubEngine> IntoIterator for AnonStake<'a, E> {
    type Item = AnonStake<'a, E>;
    type IntoIter = AnonStakeIterator<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        AnonStakeIterator {
            a: self
        }
    }
}