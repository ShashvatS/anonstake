use bellman::{Circuit, ConstraintSystem, SynthesisError, Variable, LinearCombination};
use zcash_primitives::jubjub::{JubjubEngine, FixedGenerators};
use rand::{thread_rng, Rng};
use ff::{Field, ScalarEngine};
use bellman::gadgets::{boolean, num, Assignment};
use zcash_proofs::circuit::pedersen_hash::pedersen_hash;
use zcash_primitives::pedersen_hash::Personalization;
use zcash_primitives::primitives::ValueCommitment;
use zcash_proofs::circuit::ecc;
use zcash_proofs::circuit::ecc::EdwardsPoint;
use bellman::gadgets::boolean::field_into_boolean_vec_le;
use bellman::gadgets::num::{AllocatedNum, Num};
use crate::constants::mimc_constants::MiMCConstants;

impl<'a, E: JubjubEngine> super::AnonStake<'a, E> {

    pub fn constrain_coin_commitment<CS>(&self, mut cs: CS, namespace: &str, a_pk: AllocatedNum<E>) -> Result<(EdwardsPoint<E>, Num<E>, AllocatedNum<E>), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        // Compute note contents:
        // value (in big endian) followed by g_d and pk_d
        let mut note_contents = vec![];

        // Handle the value; we'll need it later for the
        // dummy input check.
        let mut value_num = num::Num::<E>::zero();
        {

            // Booleanize the value into little-endian bit order
            let value_bits = boolean::u64_into_boolean_vec_le(
                cs.namespace(|| namespace.to_owned() + "value"),
                self.aux_input.coin.value,
            )?;

            // Compute the note's value as a linear combination
            // of the bits.
            let mut coeff = E::Fr::one();
            for bit in &value_bits {
                value_num = value_num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }

            // Place the value in the note
            note_contents.extend(value_bits);
        }

//        let a_pk_alloc = AllocatedNum::alloc(cs.namespace(|| "a_pk_alloc"), || self.aux_input.coin.a_pk.ok_or(SynthesisError::AssignmentMissing))?;
        let a_pk_bits = a_pk.to_bits_le(cs.namespace(|| "a_pk_bits"))?;
        let rho_alloc = AllocatedNum::alloc(cs.namespace(|| "cs alloc"), || self.aux_input.coin.rho.ok_or(SynthesisError::AssignmentMissing))?;
        let rho_bits = rho_alloc.to_bits_le(cs.namespace(|| "rho bits"))?;

        note_contents.extend(a_pk_bits);
        note_contents.extend(rho_bits);

        // Compute the hash of the note contents
        let mut cm: EdwardsPoint<E> = pedersen_hash(
            cs.namespace(|| namespace.to_owned() + "note content hash"),
            Personalization::NoteCommitment,
            &note_contents,
            self.constants.jubjub,
        )?;


        {
            // Booleanize the randomness for the note commitment
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| namespace.to_owned() + "rcm"),
                self.aux_input.coin.s
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| namespace.to_owned() + "computation of commitment randomness"),
                FixedGenerators::NoteCommitmentRandomness,
                &rcm,
                self.constants.jubjub
            )?;

            // Randomize the note commitment. Pedersen hashes are not
            // themselves hiding commitments.
            cm = cm.add(
                cs.namespace(|| namespace.to_owned() + "randomization of note commitment"),
                &rcm,
                self.constants.jubjub
            )?;
        }


        Ok((cm, value_num, rho_alloc))
    }

    //copied directly from zcash
    pub fn coin_commitment_membership<CS>(&self, mut cs: CS, namespace: &str, cm: EdwardsPoint<E>) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = cm.get_x().clone();

        // Ascend the merkle tree authentication path
        for (i, e) in self.aux_input.cm_merkle_path.as_slice().iter().enumerate() {
//        for (i, e) in self.aux_input.cm_merkle_path.clone().into_iter().enumerate() {
            let cs = &mut cs.namespace(|| namespace.to_owned() + format!("merkle tree hash {}", i).as_ref());

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1),
            )?);

            // Push this boolean for nullifier computation later

            //not sure what this is for, apperently used to calculated the nullifier?
            //nullifier is the serial number, it seems that this bit is used to modify the serial number...
            //for some sort of attack not covered by Zerocash paper?
            //will not use in self bc research codez
            //position_bits.push(cur_is_right.clone());

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element =
                num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(e.get()?.0))?;

            // Swap the two if the current subtree is on the right
            let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right,
            )?;

            // We don't need to be strict, because the function is
            // collision-resistant. If the prover witnesses a congruency,
            // they will be unable to find an authentication path in the
            // tree with high probability.
            let mut preimage = vec![];
            preimage.extend(xl.to_bits_le(cs.namespace(|| "xl into bits"))?);
            preimage.extend(xr.to_bits_le(cs.namespace(|| "xr into bits"))?);

            // Compute the new subtree value
            cur = pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                Personalization::MerkleTree(i),
                &preimage,
                self.constants.jubjub,
            )?
                .get_x()
                .clone(); // Injective encoding
        }

        {
            let real_anchor_value = self.pub_input.root_cm;

            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                Ok(*real_anchor_value.get()?)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
//        cs.enforce(
//            || "conditionally enforce correct root",
//            |lc| lc + cur.get_variable() - rt.get_variable(),
//            |lc| lc + &value_num.lc(E::Fr::one()),
//            |lc| lc,
//        );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "anchor"))?;

            Ok(())
        }
    }

    //input: already allocated
    //sk: already allocated
    //output
    pub fn mimc_round<CS>(&self, mut cs: CS, namespace: &str, sk: &AllocatedNum<E>, input: AllocatedNum<E>, round_constant: E::Fr, cur_round: usize) -> Result<AllocatedNum<E>, SynthesisError>
    where CS: ConstraintSystem<E>
    {
        let g = || {
            match sk.get_value().ok_or(SynthesisError::AssignmentMissing) {
                Ok(sk2) => {
                    match input.get_value().ok_or(SynthesisError::AssignmentMissing) {
                        Ok(input2) => {
                            let mut val = sk2.clone();
                            val.add_assign(&input2);
                            val.add_assign(&round_constant);
                            Ok(val)
                        },
                        Err(e) => Err(e)
                    }
                },
                Err(e) => Err(e)
            }
        };


        let f = || {
            match g() {
                Ok(mut s) => {
                    s.square();
                    Ok(s)
                },
                Err(e) => Err(e)
            }
        };

        let square_namespace = namespace.to_owned() + "first square round: " + cur_round.to_string().as_ref();
        let mut square = AllocatedNum::alloc(cs.namespace(|| square_namespace), f)?;

        cs.enforce(|| "first square",
                   |lc| lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
                   |lc| lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
                   |lc| lc + square.get_variable());


        for i in 1..self.constants.mimc.exponent {
            square = square.square(cs.namespace(|| namespace.to_owned() + "square #" + i.to_string().as_ref()))?;
        }

        let curpower = square;
        let f = || {
            match curpower.get_value().ok_or(SynthesisError::AssignmentMissing) {
                Ok(s) => {
                    match g() {
                        Ok(ss) => {
                            if let Some(mut ssinv) = ss.inverse() {
                                ssinv.mul_assign(&s);
                                Ok(ssinv)
                            } else {
                                Err(SynthesisError::DivisionByZero)
                            }
                        },
                        Err(e) => Err(e)
                    }
                },
                Err(e) => Err(e)
            }
        };

        let output_namespace = namespace.to_owned() + "output: " + cur_round.to_string().as_ref();
        let output = AllocatedNum::alloc(cs.namespace(||output_namespace), f)?;

        cs.enforce(|| "round output",
        |lc|lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
        |lc|lc + output.get_variable(),
        |lc|lc + curpower.get_variable());

        Ok(output)
    }

    pub fn mimc_prf<CS>(&self, mut cs: CS, namespace: &str, sk: AllocatedNum<E>, input: AllocatedNum<E>, mimc_constants: &[E::Fr; 162]) -> Result<AllocatedNum<E>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut input = input;

        for i in 0..self.constants.mimc.num_rounds - 1 {
            let namespace = namespace.to_owned() + "round " + i.to_string().as_ref();
            input = self.mimc_round(cs.namespace(|| namespace.to_owned() + "round " + i.to_string().as_ref()), namespace.as_ref(), &sk, input, mimc_constants[i], i)?;
        }

        {
            let cur_round = self.constants.mimc.num_rounds - 1;
            let round_constant = mimc_constants[cur_round].clone();

            let g = || {
                match sk.get_value().ok_or(SynthesisError::AssignmentMissing) {
                    Ok(sk2) => {
                        match input.get_value().ok_or(SynthesisError::AssignmentMissing) {
                            Ok(input2) => {
                                let mut val = sk2.clone();
                                val.add_assign(&input2);
                                val.add_assign(&round_constant);
                                Ok(val)
                            },
                            Err(e) => Err(e)
                        }
                    },
                    Err(e) => Err(e)
                }
            };


            let f = || {
                match g() {
                    Ok(mut s) => {
                        s.square();
                        Ok(s)
                    },
                    Err(e) => Err(e)
                }
            };

            let square_namespace = namespace.to_owned() + "first square round: " + cur_round.to_string().as_ref();
            let mut square = AllocatedNum::alloc(cs.namespace(|| square_namespace), f)?;

            cs.enforce(|| "first square",
                       |lc| lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
                       |lc| lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
                       |lc| lc + square.get_variable());

            for i in 1..self.constants.mimc.exponent {
                square = square.square(cs.namespace(|| namespace.to_owned() + "square #" + i.to_string().as_ref()))?;
            }

            let curpower = square;
            let f = || {
                match curpower.get_value().ok_or(SynthesisError::AssignmentMissing) {
                    Ok(s) => {
                        match g() {
                            Ok(ss) => {
                                if let Some(mut ssinv) = ss.inverse() {
                                    ssinv.mul_assign(&s);
                                    ssinv.add_assign(sk.clone().get_value().get()?);
                                    Ok(ssinv)
                                } else {
                                    Err(SynthesisError::DivisionByZero)
                                }
                            },
                            Err(e) => Err(e)
                        }
                    },
                    Err(e) => Err(e)
                }
            };

            let output_namespace = namespace.to_owned() + "output: " + cur_round.to_string().as_ref();
            let output = AllocatedNum::alloc(cs.namespace(||output_namespace), f)?;

            cs.enforce(|| "round output",
                       |lc|lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
                       |lc|lc + output.get_variable() - sk.get_variable(),
                       |lc|lc + curpower.get_variable());

            Ok(output)
        }
    }

}




