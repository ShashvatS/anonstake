use bellman::{Circuit, ConstraintSystem, SynthesisError};
use zcash_primitives::jubjub::JubjubEngine;
use ff::{Field, PrimeField};

pub mod anonstake_inputs;

use anonstake_inputs::*;
use bellman::gadgets::boolean::{Boolean, AllocatedBit};
use bellman::gadgets::{num, boolean};
use bellman::gadgets::num::{AllocatedNum, Num};

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
        let a_sk = AllocatedNum::alloc(cs.namespace(|| "a_sk"), || self.aux_input.a_sk.ok_or(SynthesisError::AssignmentMissing))?;

        //kind of hacky but whatever, do not have enough time
        let allocated_zero = AllocatedNum::alloc(cs.namespace(|| "allocate fake zero"), || Ok(E::Fr::zero()))?;

        let a_pk = self.mimc_prf(cs.namespace(|| "calc a_pk"), "calc a_pk", a_sk.clone(), allocated_zero.clone(), &self.constants.mimc.prf_addr)?;

        let (role, role_bits, fs_start_bits, fs_pk) = self.forward_secure_tree(
            cs.namespace(|| "forward secure tree"), "forward secure tree")?;

        let rho = AllocatedNum::alloc(cs.namespace(|| "rho alloc"),
                                            || self.aux_input.coin.rho.ok_or(SynthesisError::AssignmentMissing))?;

        let full_pk = self.constrain_full_pk(
            cs.namespace(|| "constrain packed values"),
            "constrain packed values", fs_start_bits, fs_pk, a_pk.clone())?;

        let (cm, _value, value_bits) = self.constrain_coin_commitment(
            cs.namespace(|| "coin commitment computation"),
            "coin commitment computation", full_pk, rho.clone())?;
        self.coin_commitment_membership(cs.namespace(|| "coin commitment membership"), "coin commitment membership", cm)?;

        let seed_sel = AllocatedNum::alloc(cs.namespace(|| "allocate seed_sel"), || self.pub_input.seed.ok_or(SynthesisError::AssignmentMissing))?;
        seed_sel.inputize(cs.namespace(|| "inputize seed_sel"))?;

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

        let j_i = {
            let mut coeff = E::Fr::one();
            let mut num = Num::zero();

            for bit in &j_i_bits {
                num = num.add_bool_with_coeff(CS::one(), bit, E::Fr::one());
                coeff.double();
            }

            num
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

            let sn_box = if self.use_poseidon {
                self.crh_poseidon_or_pedersen_elems(cs.namespace(|| "calc sn box"), "calc sn_box", sn_less, sn_plus)?
            } else {
                let mut all_bits = sn_less_bits;
                all_bits.extend(sn_plus_bits);
                self.crh(cs.namespace(|| "calc sn box"), "calc sn_box", all_bits.as_ref())?
            };

            self.serial_number_nonmembership(cs.namespace(|| "sn merkle"), "sn merkle", sn_box)?;
        }

        {
            let hash = if self.use_poseidon {
                let a = [Num::from(rho.clone()), Num::from(role.clone()), j_i.clone(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero()];

                let hash = self.poseidon(cs.namespace(|| "prehash calc tsn"), "prehash calc tsn", a)?;

                let allocated_num = AllocatedNum::alloc(
                    cs.namespace(|| "allocate hash for tsn calc"),
                    || hash.get_value().ok_or(SynthesisError::AssignmentMissing))?;

                cs.enforce(|| "ensure poseidon hash value = allocated num for h calc",
                           |_| hash.lc(E::Fr::one()),
                           |lc| lc + CS::one(),
                           |lc| lc + allocated_num.get_variable());

                allocated_num
            }
            else {
                let mut all_bits = rho.to_bits_le(cs.namespace(|| "rho bits"))?;

                all_bits.extend(role_bits.clone());
                all_bits.extend(j_i_bits.clone());
                self.crh(cs.namespace(|| "prehash calc tsn"), "prehash calc tsn", all_bits.as_ref())?
            };

            let tsn = self.mimc_prf(cs.namespace(|| "calc tsn"), "calc tsn", a_sk.clone(), hash, &self.constants.mimc.prf_tsn)?;
            tsn.inputize(cs.namespace(|| "inputize tsn"))?;
        }

        {
            let h_sig = AllocatedNum::alloc(cs.namespace(|| "allocate h_sig"), || self.pub_input.h_sig.ok_or(SynthesisError::AssignmentMissing))?;
            h_sig.inputize(cs.namespace(|| "inputize h_sig"))?;

            let hash = if self.use_poseidon {
                let a = [Num::from(h_sig), Num::from(role.clone()), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero()];

                let hash = self.poseidon(cs.namespace(|| "prehash calc for h"), "prehash calc for h", a)?;

                let allocated_num = AllocatedNum::alloc(
                    cs.namespace(|| "allocate hash for h calc"),
                    || hash.get_value().ok_or(SynthesisError::AssignmentMissing))?;

                cs.enforce(|| "ensure poseidon hash value = allocated num for tsn calc",
                           |_| hash.lc(E::Fr::one()),
                           |lc| lc + CS::one(),
                           |lc| lc + allocated_num.get_variable());

                allocated_num
            }
            else {
                let mut all_bits = h_sig.to_bits_le(cs.namespace(|| "h_sig to bits"))?;
                all_bits.extend(role_bits.clone());

                self.crh(cs.namespace(|| "hash for calc h"), "hash for calc h", all_bits.as_ref())?
            };


            let h = self.mimc_prf(cs.namespace(|| "calc h"), "calc h", a_sk.clone(), hash, &self.constants.mimc.prf_pk)?;
            h.inputize(cs.namespace(|| "inputize h"))?;
        }

        if self.is_bp {
            let hash = if self.use_poseidon {
                let a = [Num::from(role.clone()), Num::from(seed_sel.clone()), j_i.clone(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero()];

                let hash = self.poseidon(cs.namespace(|| "prehash calc priority"), "prehash calc tsn", a)?;

                let allocated_num = AllocatedNum::alloc(
                    cs.namespace(|| "allocate hash for priority"),
                    || hash.get_value().ok_or(SynthesisError::AssignmentMissing))?;

                cs.enforce(|| "ensure poseidon hash value = allocated num for priority calc",
                           |_| hash.lc(E::Fr::one()),
                           |lc| lc + CS::one(),
                           |lc| lc + allocated_num.get_variable());

                allocated_num
            } else {
                let mut all_bits = role_bits.clone();
                all_bits.extend(seed_sel_bits);
                all_bits.extend(j_i_bits.clone());

                self.crh(cs.namespace(|| "prehash calc priority"), "prehash calc priority", all_bits.as_ref())?
            };

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

            let num = {
                let mut num = num::Num::zero();
                let mut coeff = E::Fr::one();
                for bit in &round_bits {
                    num = num.add_bool_with_coeff(CS::one(), bit, coeff);
                    coeff.double();
                }

                num
            };

            cs.enforce(|| "round bits enforce",
                       |lc| lc + round.get_variable(),
                       |lc| lc + CS::one(),
                       |_| num.lc(E::Fr::one()));

            let mut all_bits = round_bits;
            all_bits.extend(j_i_bits);

            let hash = self.crh(cs.namespace(|| "prehash calc seed_comp"), "prehash calc seed_comp", all_bits.as_ref())?;

            let seed_comp = self.mimc_prf(cs.namespace(|| "calc seed_comp"), "calc seed_comp", a_sk.clone(), hash, &self.constants.mimc.prf_seed)?;
            seed_comp.inputize(cs.namespace(|| "inputize seed_comp"))?;
        }

        Ok(())
    }
}

pub struct AnonStakeIterator<'a, E: JubjubEngine> {
    a: AnonStake<'a, E>
}

impl<'a, E: JubjubEngine> AnonStakeIterator<'a, E> {
    pub fn get_copy(&self) -> Option<AnonStake<'a, E>> {
        Some(self.a.clone())
    }
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