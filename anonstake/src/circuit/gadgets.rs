use std::io::Cursor;

use bellman::{ConstraintSystem, LinearCombination, SynthesisError, Variable};
use bellman::gadgets::{Assignment, boolean, num};
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::num::{AllocatedNum, Num};
use ff::{Field, PrimeField, PrimeFieldRepr};
use zcash_primitives::jubjub::{FixedGenerators, JubjubEngine, ToUniform};
use zcash_primitives::pedersen_hash::Personalization;
use zcash_primitives::redjubjub;
use zcash_proofs::circuit::ecc;
use zcash_proofs::circuit::ecc::{EdwardsPoint, fixed_base_multiplication};
use zcash_proofs::circuit::pedersen_hash::pedersen_hash;

impl<'a, E: JubjubEngine> super::AnonStake<'a, E> {
    pub fn poseidon_sbox<CS>(&self, mut cs: CS, namespace: &str, num: &Num<E>) -> Result<AllocatedNum<E>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let square = AllocatedNum::alloc(
            cs.namespace(|| format!("{}: square", namespace)), || {
                let mut tmp = num.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                tmp.square();
                Ok(tmp)
            },
        )?;

        cs.enforce(|| format!("{}: enforce square", namespace),
                   |_| num.lc(E::Fr::one()),
                   |_| num.lc(E::Fr::one()),
                   |lc| lc + square.get_variable());

        let square_square = square.square(cs.namespace(|| format!("{}: square square", namespace)))?;

        let ans = AllocatedNum::alloc(
            cs.namespace(|| format!("{}: final", namespace)), || {
                let mut tmp = num.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                tmp.mul_assign(&square_square.get_value().ok_or(SynthesisError::AssignmentMissing)?);
                Ok(tmp)
            },
        )?;

        cs.enforce(|| format!("{}: enforce final", namespace),
                   |_| num.lc(E::Fr::one()),
                   |lc| lc + square_square.get_variable(),
                   |lc| lc + ans.get_variable());

        Ok(ans)
    }

    pub fn poseidon_round<CS>(&self, mut cs: CS, namespace: &str, mut input: [Num<E>; 9], round: usize) -> Result<[Num<E>; 9], SynthesisError>
        where CS: ConstraintSystem<E>
    {
        if round < self.constants.poseidon.r_f / 2 || round >= self.constants.poseidon.r_p + self.constants.poseidon.r_f / 2 {
            for i in 0..9 {
                let str = format!("{}: {} {}", namespace, round, i);
                let calc = self.poseidon_sbox(cs.namespace(|| str.clone()), str.as_ref(), &input[i])?;
                input[i] = Num::from(calc);
            }
        } else {
            for i in 0..1 {
                let str = format!("{}: {} {}", namespace, round, i);
                let calc = self.poseidon_sbox(cs.namespace(|| str.clone()), str.as_ref(), &input[i])?;
                input[i] = Num::from(calc);
            }
        }

        let mut output: [Num<E>; 9] = [Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero()];

        for i in 0..9 {
            for j in 0..9 {
                output[i] = output[i].clone() + input[j].multiply(self.constants.poseidon.mds[i][j]);
            }
        }

        for i in 0..9 {
            let mut o = output[i].clone();
            o = o.add_bool_with_coeff(CS::one(), &Boolean::constant(true), self.constants.poseidon.rounds[round][i]);
            output[i] = o;
            output[i].simplify();
        }

        Ok(output)
    }

    pub fn poseidon<CS>(&self, mut cs: CS, namespace: &str, input: [Num<E>; 8]) -> Result<Num<E>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut state: [Num<E>; 9] = [Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero()];
        for i in 0..8 {
            state[i] = input[i].clone();
        }

        for round in 0..(self.constants.poseidon.r_f + self.constants.poseidon.r_p) {
            let namespace = format!("{}: {}", namespace, round);
            state = self.poseidon_round(cs.namespace(|| namespace.clone()), namespace.as_str(), state, round)?;
        }

        Ok(state[0].clone())
    }

    pub fn crh_poseidon_or_pedersen_elem_with_zero<CS>(&self, mut cs: CS, namespace: &str, num: AllocatedNum<E>) -> Result<AllocatedNum<E>, SynthesisError>
        where CS: ConstraintSystem<E> {
        if self.use_poseidon {
            let num: Num<E> = num.into();
            let result = self.poseidon(
                cs.namespace(|| format!("{} poseidon", namespace)),
                &format!("{} poseidon", namespace),
                [num, Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero()],
            )?;

            let allocated_num = AllocatedNum::alloc(
                cs.namespace(|| format!("{} allocate result", namespace)),
                || result.get_value().ok_or(SynthesisError::AssignmentMissing))?;

            cs.enforce(|| format!("{} ensure poseidon hash value = allocated num", namespace),
                       |_| result.lc(E::Fr::one()),
                       |lc| lc + CS::one(),
                       |lc| lc + allocated_num.get_variable());

            return Ok(allocated_num);
        } else {
            let bits = num.to_bits_le(
                cs.namespace(|| format!("{} to bits", namespace)))?;
            return self.crh(cs, namespace, bits.as_slice());
        }
    }

    pub fn crh_poseidon_or_pedersen_elems<CS>(&self, mut cs: CS, namespace: &str, num1: AllocatedNum<E>, num2: AllocatedNum<E>) -> Result<AllocatedNum<E>, SynthesisError>
        where CS: ConstraintSystem<E> {
        if self.use_poseidon {
            let num1: Num<E> = num1.into();
            let num2: Num<E> = num2.into();
            let result = self.poseidon(
                cs.namespace(|| format!("{} poseidon", namespace)),
                &format!("{} poseidon", namespace),
                [num1, num2, Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero(), Num::zero()],
            )?;

            let allocated_num = AllocatedNum::alloc(
                cs.namespace(|| format!("{} allocate result", namespace)),
                || result.get_value().ok_or(SynthesisError::AssignmentMissing))?;

            cs.enforce(|| format!("{} ensure poseidon hash value = allocated num", namespace),
                       |_| result.lc(E::Fr::one()),
                       |lc| lc + CS::one(),
                       |lc| lc + allocated_num.get_variable());

            return Ok(allocated_num);
        } else {
            let mut bits = num1.to_bits_le(
                cs.namespace(|| format!("{} to bits", namespace)))?;
            bits.extend(num2.to_bits_le(
                cs.namespace(|| format!("{} to bits 2", namespace)))?);
            return self.crh(cs, namespace, bits.as_slice());
        }
    }

    pub fn get_role_bits<CS>(&self, mut cs: CS, namespace: &str) -> Result<(AllocatedNum<E>, Vec<Boolean>), SynthesisError>
        where CS: ConstraintSystem<E> {
        let mut role_num = num::Num::<E>::zero();

        // Booleanize the value into little-endian bit order
        let role_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| namespace.to_owned() + "value"),
            self.pub_input.role,
        )?;

        {
            let mut coeff = E::Fr::one();
            for bit in &role_bits {
                role_num = role_num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }
        }

        let role = AllocatedNum::alloc(cs.namespace(|| namespace.to_owned() + "allocate role"),
                                       || role_num.get_value().ok_or(SynthesisError::AssignmentMissing))?;
        role.inputize(cs.namespace(|| namespace.to_owned() + "inputize role"))?;

        Ok((role, role_bits))
    }

    pub fn constrain_coin_commitment<CS>(&self, mut cs: CS, namespace: &str, a_pk: AllocatedNum<E>, pack: AllocatedNum<E>) -> Result<(EdwardsPoint<E>, Num<E>, Vec<Boolean>), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        // Compute note contents:
        // value (in big endian) followed by g_d and pk_d
        let mut note_contents = vec![];

        // Handle the value; we'll need it later for the
        // dummy input check.
        let mut value_num = num::Num::<E>::zero();

        // Booleanize the value into little-endian bit order
        let value_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| namespace.to_owned() + "value"),
            self.aux_input.coin.value,
        )?;

        {
            // Compute the note's value as a linear combination
            // of the bits.
            let mut coeff = E::Fr::one();

            for bit in &value_bits {
                value_num = value_num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }

            // Place the value in the note
            note_contents.extend(value_bits.clone());
        }

//        let a_pk_alloc = AllocatedNum::alloc(cs.namespace(|| "a_pk_alloc"), || self.aux_input.coin.a_pk.ok_or(SynthesisError::AssignmentMissing))?;
        let a_pk_bits = a_pk.to_bits_le(cs.namespace(|| "a_pk_bits"))?;
        let pack_bits = pack.to_bits_le(cs.namespace(|| "pack bits"))?;

        note_contents.extend(a_pk_bits);
        note_contents.extend(pack_bits);

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
                self.aux_input.coin.s,
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| namespace.to_owned() + "computation of commitment randomness"),
                FixedGenerators::NoteCommitmentRandomness,
                &rcm,
                self.constants.jubjub,
            )?;

            // Randomize the note commitment. Pedersen hashes are not
            // themselves hiding commitments.
            cm = cm.add(
                cs.namespace(|| namespace.to_owned() + "randomization of note commitment"),
                &rcm,
                self.constants.jubjub,
            )?;
        }

        Ok((cm, value_num, value_bits))
    }

    pub fn constrain_packed_values<CS>(&self, mut cs: CS, namespace: &str, fs_start_bits: Vec<Boolean>, fs_pk: AllocatedNum<E>) -> Result<(AllocatedNum<E>, AllocatedNum<E>), SynthesisError>
        where CS: ConstraintSystem<E> {
        let rho_alloc = AllocatedNum::alloc(cs.namespace(|| "cs alloc"),
                                            || self.aux_input.coin.rho.ok_or(SynthesisError::AssignmentMissing))?;
        let rho_bits = rho_alloc.to_bits_le(cs.namespace(|| "rho bits"))?;

        let fs_pk_bits = fs_pk.to_bits_le(cs.namespace(|| "fs_pk_bits"))?;

        let mut bits = fs_start_bits;
        bits.extend(fs_pk_bits);
        bits.extend(rho_bits);

        let hash_point: EdwardsPoint<E> = pedersen_hash(
            cs.namespace(|| namespace.to_owned() + "compute hash"),
            Personalization::NoteCommitment,
            &bits,
            self.constants.jubjub,
        )?;

        let pack = hash_point.get_x().clone();

        Ok((rho_alloc, pack))
    }

    //copied directly from zcash
    pub fn coin_commitment_membership1<CS>(&self, mut cs: CS, namespace: &str, cm: EdwardsPoint<E>) -> Result<(), SynthesisError>
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
                cs.namespace(|| "comthe original Zerocash paper even though we are creating a zero-knowledge proof for a muchmore complex statement.In the future, we would like to create an implementation of our scheme. However, this iscurrently impossible. We extensively use the MiMC block cipher in our scheme. Because ofits design, MiMC can only be used in a prime fieldFpwheregcd(3,p−1) = 1. Unfortunately,neither the libsnark library nor the bellman library for constructing zk-SNARKs have suitablefields.  MiMC  also  needs  to  be  more  thoroughly  analyzed.  Currently,  the  only  publishedcryptoanalysis on MiMC was done by the authors themselves.6    Ackputation of pedersen hash"),
                Personalization::MerkleTree(i),
                &preimage,
                self.constants.jubjub,
            )?
                .get_x()
                .clone(); // Injective encoding
        }

        {
//            let real_anchor_value = self.pub_input.root_cm;

            //slightly lazy, allocating an extra variable, whatever

            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                cur.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
            cs.enforce(
                || "conditionally enforce correct root",
                |lc| lc + cur.get_variable() - rt.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "anchor"))?;

            Ok(())
        }
    }

    pub fn coin_commitment_membership2<CS>(&self, mut cs: CS, namespace: &str, cm: EdwardsPoint<E>) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let cur = cm.get_x().clone();
        let mut cur = Num::from(cur);

        // Ascend the merkle tree authentication path
        for (i, e) in self.aux_input.cm_poseidon_path.as_slice().iter().enumerate() {
            let mut cur_path_num = {
                let mut cur_path: Vec<AllocatedNum<E>> = vec![];
                for j in 0..8 {
                    let str = format!("{}: merkle tree hash height {} alloc i {}", namespace, i, j);
                    let num = AllocatedNum::alloc(cs.namespace(|| str), || {
                        let t = e.ok_or(SynthesisError::AssignmentMissing)?;
                        if t.1 == j {
                            return cur.get_value().ok_or(SynthesisError::AssignmentMissing);
                        } else {
                            return Ok(t.0[j as usize]);
                        }
                    })?;

                    cur_path.push(num);
                }

                let mut cur_path_num = vec![];
                for num in cur_path {
                    cur_path_num.push(Num::from(num));
                }

                cur_path_num
            };

            let t = [cur_path_num[0].clone(), cur_path_num[1].clone(), cur_path_num[2].clone(), cur_path_num[3].clone(), cur_path_num[4].clone(), cur_path_num[5].clone(), cur_path_num[6].clone(), cur_path_num[7].clone()];
            let next_cur = self.poseidon(cs.namespace(|| namespace.to_owned() + format!("merkle tree hash {}", i).as_ref()), (namespace.to_owned() + format!("merkle tree hash {}", i).as_ref()).as_ref(), t)?;

            let mut minus_one = E::Fr::one();
            minus_one.negate();
            let minus_cur = cur.multiply(minus_one);

            for i in 0..8 {
                cur_path_num[i] = cur_path_num[i].clone() + minus_cur.clone();
                cur_path_num[i].simplify();
            }

            let mut var = AllocatedNum::alloc(
                cs.namespace(|| format!("{}: {} {} constrain 0", namespace, i, 1)),
                || {
                    let mut tmp = cur_path_num[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
                    tmp.mul_assign(&cur_path_num[1].get_value().ok_or(SynthesisError::AssignmentMissing)?);
                    Ok(tmp)
                },
            )?;

            cs.enforce(|| format!("{}: {} {} constrain constraint 0", namespace, i, 1),
                       |_| cur_path_num[0].lc(E::Fr::one()),
                       |_| cur_path_num[1].lc(E::Fr::one()),
                       |lc| lc + var.get_variable());

            for j in 2..8 {
                let new_var = AllocatedNum::alloc(
                    cs.namespace(|| format!("{}: {} {} constrain 0", namespace, i, j)),
                    || {
                        let mut tmp = var.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                        tmp.mul_assign(&cur_path_num[j].get_value().ok_or(SynthesisError::AssignmentMissing)?);
                        Ok(tmp)
                    },
                )?;

                cs.enforce(|| format!("{}: {} {} constrain constraint 0", namespace, i, j),
                           |_| cur_path_num[j].lc(E::Fr::one()),
                           |lc| lc + var.get_variable(),
                           |lc| lc + new_var.get_variable());

                var = new_var;
            }

            cs.enforce(|| format!("{}: {} {} constrain constraint sksk 0", namespace, i, 1),
                       |lc| lc + var.get_variable(),
                       |lc| lc + CS::one(),
                       |lc| lc);

            cur = next_cur;
        }

        {
            //slightly lazy, allocating an extra variable, whatever

            //Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                cur.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
            cs.enforce(
                || "conditionally enforce correct root",
                |_| cur.lc(E::Fr::one()) - rt.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "anchor"))?;
        }

        Ok(())
    }

    pub fn coin_commitment_membership<CS>(&self, cs: CS, namespace: &str, cm: EdwardsPoint<E>) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        if self.use_poseidon {
            self.coin_commitment_membership2(cs, namespace, cm)
        } else {
            self.coin_commitment_membership1(cs, namespace, cm)
        }
    }

    //modified from above
    pub fn serial_number_nonmembership1<CS>(&self, mut cs: CS, namespace: &str, sn_box: AllocatedNum<E>) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = sn_box;

        // Ascend the merkle tree authentication path
        for (i, e) in self.aux_input.sn_merkle_path.as_slice().iter().enumerate() {
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
                cs.namespace(|| "comthe original Zerocash paper even though we are creating a zero-knowledge proof for a muchmore complex statement.In the future, we would like to create an implementation of our scheme. However, this iscurrently impossible. We extensively use the MiMC block cipher in our scheme. Because ofits design, MiMC can only be used in a prime fieldFpwheregcd(3,p−1) = 1. Unfortunately,neither the libsnark library nor the bellman library for constructing zk-SNARKs have suitablefields.  MiMC  also  needs  to  be  more  thoroughly  analyzed.  Currently,  the  only  publishedcryptoanalysis on MiMC was done by the authors themselves.6    Ackputation of pedersen hash"),
                Personalization::MerkleTree(i),
                &preimage,
                self.constants.jubjub,
            )?
                .get_x()
                .clone(); // Injective encoding
        }

        {
            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "sn conditional anchor"), || {
                cur.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
            cs.enforce(
                || "conditionally enforce correct root",
                |lc| lc + cur.get_variable() - rt.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "sn anchor"))?;

            Ok(())
        }
    }


    //modified from above
    pub fn serial_number_nonmembership2<CS>(&self, mut cs: CS, namespace: &str, sn_box: AllocatedNum<E>) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let cur = sn_box;
        let mut cur = Num::from(cur);

        // Ascend the merkle tree authentication path
        for (i, e) in self.aux_input.sn_poseidon_path.as_slice().iter().enumerate() {
            let mut cur_path: Vec<AllocatedNum<E>> = vec![];
            for j in 0..8 {
                let str = format!("{}: merkle tree hash height {} alloc i {}", namespace, i, j);
                let num = AllocatedNum::alloc(cs.namespace(|| str), || {
                    let t = e.ok_or(SynthesisError::AssignmentMissing)?;
                    if t.1 == j {
                        return cur.get_value().ok_or(SynthesisError::AssignmentMissing);
                    } else {
                        return Ok(t.0[j as usize]);
                    }
                })?;

                cur_path.push(num);
            }

            let mut cur_path_num = vec![];
            for num in cur_path {
                cur_path_num.push(Num::from(num));
            }

            let t = [cur_path_num[0].clone(), cur_path_num[1].clone(), cur_path_num[2].clone(), cur_path_num[3].clone(), cur_path_num[4].clone(), cur_path_num[5].clone(), cur_path_num[6].clone(), cur_path_num[7].clone()];

            let next_cur = self.poseidon(cs.namespace(|| namespace.to_owned() + format!("merkle tree hash {}", i).as_ref()), (namespace.to_owned() + format!("merkle tree hash {}", i).as_ref()).as_ref(), t)?;

            let mut minus_one = E::Fr::one();
            minus_one.negate();
            let minus_cur = cur.multiply(minus_one);

            for i in 0..8 {
                cur_path_num[i] = cur_path_num[i].clone() + minus_cur.clone();
                cur_path_num[i].simplify();
            }

            let mut var = AllocatedNum::alloc(
                cs.namespace(|| format!("{}: {} {} constrain 0", namespace, i, 1)),
                || {
                    let mut tmp = cur_path_num[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
                    tmp.mul_assign(&cur_path_num[1].get_value().ok_or(SynthesisError::AssignmentMissing)?);
                    Ok(tmp)
                },
            )?;

            cs.enforce(|| format!("{}: {} {} constrain constraint 0", namespace, i, 1),
                       |_| cur_path_num[0].lc(E::Fr::one()),
                       |_| cur_path_num[1].lc(E::Fr::one()),
                       |lc| lc + var.get_variable());

            for j in 2..8 {
                let new_var = AllocatedNum::alloc(
                    cs.namespace(|| format!("{}: {} {} constrain 0", namespace, i, j)),
                    || {
                        let mut tmp = var.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                        tmp.mul_assign(&cur_path_num[j].get_value().ok_or(SynthesisError::AssignmentMissing)?);
                        Ok(tmp)
                    },
                )?;

                cs.enforce(|| format!("{}: {} {} constrain constraint 0", namespace, i, j),
                           |_| cur_path_num[j].lc(E::Fr::one()),
                           |lc| lc + var.get_variable(),
                           |lc| lc + new_var.get_variable());

                var = new_var;
            }

            cs.enforce(|| format!("{}: {} {} constrain constraint sksk 0", namespace, i, 1),
                       |lc| lc + var.get_variable(),
                       |lc| lc + CS::one(),
                       |lc| lc);

            cur = next_cur;
        }

        {
            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "sn conditional anchor"), || {
                cur.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
            cs.enforce(
                || "conditionally enforce correct root",
                |_| cur.lc(E::Fr::one()) - rt.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "sn anchor"))?;
        }

        Ok(())
    }

    //modified from above
    pub fn serial_number_nonmembership<CS>(&self, cs: CS, namespace: &str, sn_box: AllocatedNum<E>) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        if self.use_poseidon {
            self.serial_number_nonmembership2(cs, namespace, sn_box)
        } else {
            self.serial_number_nonmembership1(cs, namespace, sn_box)
        }
    }


    pub fn forward_secure_tree_main<CS>(&self, mut cs: CS, namespace: &str, time: AllocatedNum<E>) -> Result<AllocatedNum<E>, SynthesisError>
        where CS: ConstraintSystem<E>, E::Fs: ToUniform {
        let time_bits: Vec<Boolean> = {
            let tmp = if let (Some(a), Some(b)) = (self.pub_input.role, self.aux_input.fs_tree_start) {
                Some(a - b)
            } else {
                None
            };

            let mut bits = boolean::u64_into_boolean_vec_le(
                cs.namespace(|| format!("{} get time diff bits", namespace)), tmp)?;
            bits.truncate(36);

            let time_bits = bits;

            let mut time_num = num::Num::<E>::zero();

            let mut coeff = E::Fr::one();
            for bit in &time_bits {
                time_num = time_num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }

            cs.enforce(|| format!("{} enforce time valid", namespace),
                       |_| time_num.lc(E::Fr::one()),
                       |lc| lc + CS::one(),
                       |lc| lc + time.get_variable());

            time_bits
        };

        let mut final_pks: Vec<AllocatedNum<E>> = vec![];

        //TODO: refactor this code
        for i in 0..4 {
            let bits = &time_bits[9 * i..9 * (i + 1)];

            let tree_pk = if i == 0 {
                let sk: Option<E::Fr> = {
                    let s = self.aux_input.fs_sk[i].as_ref();
                    if let Some(s) = s {
                        let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
                        s.into_repr().write_le(cursor.get_mut()).unwrap();
                        let mut read_elem = E::Fr::zero().into_repr();

                        //TODO: avoid calling unwrap
                        read_elem.read_le(cursor).unwrap();
                        Some(E::Fr::from_repr(read_elem).unwrap())
                    } else {
                        None
                    }
                };

                let sk = AllocatedNum::alloc(
                    cs.namespace(|| format!("{} allocate secret key {}", namespace, i)),
                    || sk.ok_or(SynthesisError::AssignmentMissing))?;

                let pk = self.crh_poseidon_or_pedersen_elem_with_zero(
                    cs.namespace(|| format!("{} calculate public key {}", namespace, i)),
                    &format!("{} calculate public key {}", namespace, i),
                    sk)?;

                pk
            } else {
                // https://en.wikipedia.org/wiki/Schnorr_signature
                // use schnorr signature instead of ECDSA

                // here we have access to the secret key
                // TODO: change so that the signature is already computed elsewhere
                let pk = {
                    let pk = {
                        let f = |s: &E::Fs| redjubjub::PublicKey::<E>::from_private(&redjubjub::PrivateKey(s.clone()), FixedGenerators::SpendingKeyGenerator, self.constants.jubjub);
                        self.aux_input.fs_sk[i].as_ref().map(f)
                    };

                    let pk = EdwardsPoint::witness(
                        cs.namespace(|| format!("{} public key point {}", namespace, i)),
                        pk.map(|s| s.0.clone()),
                        &self.constants.jubjub,
                    )?;

                    pk
                };

                let r = {
                    let r = {
                        let f = |s: &E::Fs| redjubjub::PublicKey::<E>::from_private(&redjubjub::PrivateKey(s.clone()), FixedGenerators::SpendingKeyGenerator, self.constants.jubjub);
                        self.aux_input.fs_rerandomize_public_key[i].as_ref().map(f)
                    };

                    let r = EdwardsPoint::witness(
                        cs.namespace(|| format!("{} r point {}", namespace, i)),
                        r.map(|s| s.0.clone()),
                        &self.constants.jubjub,
                    )?;

                    r
                };

                let e = self.crh_poseidon_or_pedersen_elems(
                    cs.namespace(|| format!("{} main check {}", namespace, i)),
                    &format!("{} main check {}", namespace, i),
                    r.get_x().clone(), final_pks[i - 1].clone())?;

                let s = AllocatedNum::alloc(
                    cs.namespace(|| format!("{} allocate s {}", namespace, i)),
                    || {
                        let k = &self.aux_input.fs_rerandomize_public_key[i];
                        let x = &self.aux_input.fs_sk[i];
                        if let (Some(k), Some(mut x), Some(e)) =
                        (k, x, e.get_value()) {
                            let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
                            e.into_repr().write_le(cursor.get_mut()).unwrap();

                            let mut vec8 = cursor.into_inner();
                            while vec8.len() < 64 {
                                vec8.push(0);
                            }

                            let e = E::Fs::to_uniform(&vec8);

                            let mut k = (*k).clone();
                            x.mul_assign(&e);
                            k.sub_assign(&x);

                            let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
                            k.into_repr().write_le(cursor.get_mut()).unwrap();
                            let mut read_elem = E::Fr::zero().into_repr();

                            //TODO: avoid calling unwrap
                            read_elem.read_le(cursor).unwrap();
                            Ok(E::Fr::from_repr(read_elem).unwrap())
                        } else {
                            Err(SynthesisError::AssignmentMissing)
                        }
                    },
                )?;

                let r2 = {
                    let s_bits = s.to_bits_le(cs.namespace(|| format!("{} s bits {}", namespace, i)))?;
                    let p1 = fixed_base_multiplication(
                        cs.namespace(|| format!("{} fixed base multiplication {}", namespace, i)),
                        FixedGenerators::SpendingKeyGenerator,
                        &s_bits,
                        &self.constants.jubjub)?;

                    let e_bits = e.to_bits_le(cs.namespace(|| format!("{} e bits {}", namespace, i)))?;

                    let p2 = pk.mul(cs.namespace(|| format!("{} point multiplication {}", namespace, i)),
                                    &e_bits, self.constants.jubjub)?;

                    p1.add(cs.namespace(|| format!("{} point add {}", namespace, i)),
                           &p2, self.constants.jubjub)?
                };

                cs.enforce(|| format!("{} main assertion {}", namespace, i),
                           |lc| lc + r.get_x().get_variable(),
                           |lc| lc + CS::one(),
                           |lc| lc + r2.get_x().get_variable());

                cs.enforce(|| format!("{} main assertion 2 {}", namespace, i),
                           |lc| lc + r.get_y().get_variable(),
                           |lc| lc + CS::one(),
                           |lc| lc + r2.get_y().get_variable());

                pk.get_x().clone()
            };

            let mut cur_value = tree_pk.clone();

            for j in 0..3 {
                let tmp = (&bits[3 * j].get_value(), &bits[3 * j + 1].get_value(), &bits[3 * j + 2].get_value());

                let idx: Option<u64> = if let (Some(a), Some(b), Some(c)) = tmp
                {
                    Some(1 * (*a as u64) + 2 * (*b as u64) + 4 * (*c as u64))
                } else {
                    None
                };

                let mut cur_path: Vec<AllocatedNum<E>> = vec![];
                for k in 0..8 {
                    let mut added = false;
                    if let Some(check) = idx {
                        if check == k {
                            cur_path.push(
                                AllocatedNum::alloc(
                                    cs.namespace(|| format!("{} allocate cur path {} {} {}", namespace, i, j, k)),
                                    || cur_value.get_value().ok_or(SynthesisError::AssignmentMissing),
                                )?
                            );
                            added = true;
                        }
                    }

                    if !added {
                        cur_path.push(
                            AllocatedNum::alloc(
                                cs.namespace(|| format!("{} allocate cur path {} {} {}", namespace, i, j, k)),
                                || self.aux_input.fs_main_tree[i][j][k as usize].clone().ok_or(SynthesisError::AssignmentMissing),
                            )?
                        );
                    }
                }

                {
                    let mut path_remaining = cur_path.clone();

                    for k in 0..3 {
                        let bit = &time_bits[9 * i + 3 * j + k];

                        let mut next_path = vec![];

                        for x in 0..(path_remaining.len() / 2) {
                            let a = path_remaining[2 * x].clone();
                            let b = path_remaining[2 * x + 1].clone();

                            //lazy selection, can make one less auxiliary variable if I wanted to
                            let (a, _) = AllocatedNum::conditionally_reverse(
                                cs.namespace(|| format!("{} select values for merkle tree stuff {} {} {} {}", namespace, i, j, k, x)),
                                &a, &b, bit)?;

                            next_path.push(a);
                        }

                        path_remaining = next_path;
                    }

                    let top = &path_remaining[0];

                    cs.enforce(|| format!("{} enforce equal merkle tree selection {} {}", namespace, i, j),
                               |lc| lc + top.get_variable(),
                               |lc| lc + CS::one(),
                               |lc| lc + cur_value.get_variable());
                }

                if self.use_poseidon {
                    let t: [Num<E>; 8] = [cur_path[0].clone().into(), cur_path[1].clone().into(), cur_path[2].clone().into(), cur_path[3].clone().into(), cur_path[4].clone().into(), cur_path[5].clone().into(), cur_path[6].clone().into(), cur_path[7].clone().into()];

                    let result = self.poseidon(
                        cs.namespace(|| format!("{} tree hash {} {}", namespace, i, j)),
                        &format!("{} tree hash {} {}", namespace, i, j),
                        t)?;

                    cur_value = AllocatedNum::alloc(
                        cs.namespace(|| format!("{} allocate result {} {}", namespace, i, j)),
                        || result.get_value().ok_or(SynthesisError::AssignmentMissing))?;

                    cs.enforce(|| format!("{} ensure poseidon hash value = allocated num {} {}", namespace, i, j),
                               |_| result.lc(E::Fr::one()),
                               |lc| lc + CS::one(),
                               |lc| lc + cur_value.get_variable());
                } else {
                    //really should use for loops...

                    let t0 = self.crh_poseidon_or_pedersen_elems(
                        cs.namespace(|| format!("{} tree hash {} {} {}", namespace, i, j, 0)),
                        &format!("{} tree hash {} {} {}", namespace, i, j, 0),
                        cur_path[0].clone(),
                        cur_path[1].clone(),
                    )?;

                    let t1 = self.crh_poseidon_or_pedersen_elems(
                        cs.namespace(|| format!("{} tree hash {} {} {}", namespace, i, j, 1)),
                        &format!("{} tree hash {} {} {}", namespace, i, j, 1),
                        cur_path[2].clone(),
                        cur_path[3].clone(),
                    )?;

                    let t2 = self.crh_poseidon_or_pedersen_elems(
                        cs.namespace(|| format!("{} tree hash {} {} {}", namespace, i, j, 2)),
                        &format!("{} tree hash {} {} {}", namespace, i, j, 2),
                        cur_path[4].clone(),
                        cur_path[5].clone(),
                    )?;

                    let t3 = self.crh_poseidon_or_pedersen_elems(
                        cs.namespace(|| format!("{} tree hash {} {} {}", namespace, i, j, 3)),
                        &format!("{} tree hash {} {} {}", namespace, i, j, 3),
                        cur_path[6].clone(),
                        cur_path[7].clone(),
                    )?;

                    let t4 = self.crh_poseidon_or_pedersen_elems(
                        cs.namespace(|| format!("{} tree hash {} {} {}", namespace, i, j, 4)),
                        &format!("{} tree hash {} {} {}", namespace, i, j, 4),
                        t0, t1)?;

                    let t5 = self.crh_poseidon_or_pedersen_elems(
                        cs.namespace(|| format!("{} tree hash {} {} {}", namespace, i, j, 5)),
                        &format!("{} tree hash {} {} {}", namespace, i, j, 5),
                        t2, t3)?;

                    cur_value = self.crh_poseidon_or_pedersen_elems(
                        cs.namespace(|| format!("{} tree hash {} {} {}", namespace, i, j, 6)),
                        &format!("{} tree hash {} {} {}", namespace, i, j, 6),
                        t4, t5)?;
                }

                final_pks.push(cur_value.clone());
            }
        }

        Ok(final_pks[3].clone())
    }


    pub fn forward_secure_tree<CS>(&self, mut cs: CS, namespace: &str) -> Result<(AllocatedNum<E>, Vec<Boolean>, Vec<Boolean>, AllocatedNum<E>), SynthesisError>
        where CS: ConstraintSystem<E> {
        let (role, role_bits) = self.get_role_bits(
            cs.namespace(|| format!("{} get role", namespace)),
            &format!("{} get role", namespace))?;

        let fs_start_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| format!("{} fs start bits", namespace)),
            self.aux_input.fs_tree_start,
        )?;

        self.leq_not_fixed(cs.namespace(|| format!("{} fs_start less than current role", namespace)),
                           &format!("{} fs_start less than current role", namespace),
                           &fs_start_bits, &role_bits)?;

        let time_diff = {
            let mut num = Num::<E>::zero();
            let mut coeff = E::Fr::one();

            for bit in &fs_start_bits {
                num = num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }

            AllocatedNum::alloc(cs.namespace(|| format!("{} get time diff", namespace)),
                                || {
                                    let mut value = role.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                                    value.sub_assign(&num.get_value().ok_or(SynthesisError::AssignmentMissing)?);
                                    Ok(value)
                                })?
        };

        let fs_pk = self.forward_secure_tree_main(
            cs.namespace(|| format!("{} main forward secure tree", namespace)),
            &format!("{} main forward secure tree", namespace),
            time_diff.clone())?;
//        let fs_pk = time_diff.clone();


        Ok((role, role_bits, fs_start_bits, fs_pk))
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
                        }
                        Err(e) => Err(e)
                    }
                }
                Err(e) => Err(e)
            }
        };


        let f = || {
            match g() {
                Ok(mut s) => {
                    s.square();
                    Ok(s)
                }
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
                        }
                        Err(e) => Err(e)
                    }
                }
                Err(e) => Err(e)
            }
        };

        let output_namespace = namespace.to_owned() + "output: " + cur_round.to_string().as_ref();
        let output = AllocatedNum::alloc(cs.namespace(|| output_namespace), f)?;

        cs.enforce(|| "round output",
                   |lc| lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
                   |lc| lc + output.get_variable(),
                   |lc| lc + curpower.get_variable());

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
                            }
                            Err(e) => Err(e)
                        }
                    }
                    Err(e) => Err(e)
                }
            };


            let f = || {
                match g() {
                    Ok(mut s) => {
                        s.square();
                        Ok(s)
                    }
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
                            }
                            Err(e) => Err(e)
                        }
                    }
                    Err(e) => Err(e)
                }
            };

            let output_namespace = namespace.to_owned() + "output: " + cur_round.to_string().as_ref();
            let output = AllocatedNum::alloc(cs.namespace(|| output_namespace), f)?;

            cs.enforce(|| "round output",
                       |lc| lc + sk.get_variable() + input.get_variable() + (round_constant, CS::one()),
                       |lc| lc + output.get_variable() - sk.get_variable(),
                       |lc| lc + curpower.get_variable());

            Ok(output)
        }
    }

    pub fn leq_fixed<CS>(&self, mut cs: CS, namespace: &str, mut bits: Vec<Option<E::Fr>>, value: E::Fr, mut num_bits: usize, actual_value_var: Variable) -> Result<Vec<Variable>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let value: Vec<bool> = {
            let mut res = vec![];
            let mut value = value.into_repr();

            for _i in 0..num_bits {
                res.push(value.is_odd());
                value.div2();
            }

            res
        };

        while num_bits > 0 && !value[num_bits - 1] {
            num_bits -= 1;
        }

        if num_bits == 0 {
            return Err(SynthesisError::Unsatisfiable);
        }

        let num_bits = num_bits;

        assert!(bits.len() >= num_bits);
        bits.truncate(num_bits);


        let mut prev_pi_val = bits[num_bits - 1];
        let mut prev_pi_var: Option<Variable> = None;

        let mut res_bits = vec![];

        for i in (0..num_bits).rev() {
            let new_bit = cs.alloc(|| format!("{}: leq_fixed allocate bit: {}", namespace, i),
                                   || bits[i].ok_or(SynthesisError::AssignmentMissing))?;

            res_bits.push(new_bit);

            if value[i] {
                if i == num_bits - 1 {
                    prev_pi_var = Some(new_bit);
                } else {
                    let new_pi = cs.alloc(|| format!("{}: leq_fixed allocate pi_i: {}", namespace, i),
                                          || {
                                              let mut x = prev_pi_val.ok_or(SynthesisError::AssignmentMissing)?;
                                              x.mul_assign(&bits[i].ok_or(SynthesisError::AssignmentMissing)?);
                                              Ok(x)
                                          })?;

                    if let Some(prev_pi) = prev_pi_var {
                        cs.enforce(|| format!("{}: constrain pi_i: {}", namespace, i),
                                   |lc| lc + prev_pi,
                                   |lc| lc + new_bit,
                                   |lc| lc + new_pi);
                    } else {
                        return Err(SynthesisError::Unsatisfiable);
                    }

                    prev_pi_var = Some(new_pi);
                    prev_pi_val = {
                        match bits[i] {
                            Some(mut t) => {
                                t.mul_assign(&prev_pi_val.ok_or(SynthesisError::Unsatisfiable)?);
                                Some(t)
                            }
                            None => None
                        }
                    };
                }

                cs.enforce(|| format!("{}: constrain bit {}", namespace, i),
                           |lc| lc + CS::one() - new_bit,
                           |lc| lc + new_bit,
                           |lc| lc);
            } else {
                if let Some(pi_var) = prev_pi_var {
                    cs.enforce(|| format!("{}: constrain bit {}", namespace, i),
                               |lc| lc + CS::one() - pi_var - new_bit,
                               |lc| lc + new_bit,
                               |lc| lc);
                } else {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
        }
        res_bits.reverse();

        let mut lc = LinearCombination::zero();
        let mut coeff = E::Fr::one();
        for i in &res_bits {
            lc = lc + (coeff, *i);
            coeff.double();
        }

        cs.enforce(|| format!("{}: constraining bits to value", namespace),
                   |_| lc,
                   |lc| lc + CS::one(),
                   |lc| lc + actual_value_var);

        Ok(res_bits)
    }

    pub fn leq_not_fixed<CS>(&self, mut cs: CS, namespace: &str, left_bits: &Vec<Boolean>, right_bits: &Vec<Boolean>) -> Result<(), SynthesisError>
        where CS: ConstraintSystem<E>
    {
        assert_eq!(left_bits.len(), right_bits.len());

        let mut pi = Boolean::Constant(true);

        for i in (0..right_bits.len()).rev() {
            let t = Boolean::and(cs.namespace(|| format!("{}: calc t_i: {}", namespace, i)),
                                 &left_bits[i].not(),
                                 &right_bits[i])?.not();

            pi = Boolean::and(cs.namespace(|| format!("{}: calc pi__i: {}", namespace, i)), &t, &pi)?;
            let d = Boolean::and(cs.namespace(|| format!("{}: calc d_i: {}", namespace, i)), &pi, &left_bits[i])?;
            cs.enforce(|| format!("{}: constrain to 0: {}", namespace, i),
                       |_| right_bits[i].not().lc(CS::one(), E::Fr::one()),
                       |_| d.lc(CS::one(), E::Fr::one()),
                       |lc| lc);
        }

        Ok(())
    }

    pub fn assignment_not_leq_not_fixed<CS>(&self, mut cs: CS, namespace: &str, left_bits: &Vec<Boolean>, right_bits: &Vec<Boolean>) -> Result<Boolean, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        assert_eq!(left_bits.len(), right_bits.len());

        let mut pi = Boolean::Constant(true);
        let mut e_arr = vec![];

        let mut sum: Num<E> = Num::zero();

        for i in (0..right_bits.len()).rev() {
            let t = Boolean::and(cs.namespace(|| format!("{}: calc t_i: {}", namespace, i)), &left_bits[i].not(), &right_bits[i])?.not();
            pi = Boolean::and(cs.namespace(|| format!("{}: calc pi__i: {}", namespace, i)), &t, &pi)?.not();
            let d = Boolean::and(cs.namespace(|| format!("{}: calc d_i: {}", namespace, i)), &pi, &left_bits[i])?.not();
            let e = Boolean::and(cs.namespace(|| format!("{}: calc e_i: {}", namespace, i)), &right_bits[i].not(), &d)?.not();

            sum = sum.add_bool_with_coeff(CS::one(), &e, E::Fr::one());
            e_arr.push(e);
        }

        let bit = {
            let b_val: Option<bool> = {
                let calc = || {
                    for bit in e_arr.as_slice() {
                        if let Some(e) = bit.get_value() {
                            if e {
                                return Some(true);
                            }
                        } else {
                            return None;
                        }
                    }

                    return Some(false);
                };

                calc()
            };

            AllocatedBit::alloc(cs.namespace(|| format!("{} allocate bit", namespace)),
                                b_val,
            )?
        };

        let sum_inv = AllocatedNum::alloc(cs.namespace(|| namespace.to_owned() + ": sum inv"), || {
            if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                let sum_val = sum.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                return sum_val.inverse().ok_or(SynthesisError::DivisionByZero);
            } else {
                return Ok(E::Fr::one());
            }
        })?;

        sum_inv.assert_nonzero(cs.namespace(|| namespace.to_owned() + "assert sum_inv non-zero"))?;

        cs.enforce(|| namespace.to_owned() + "assert b correct",
                   |_| sum.lc(E::Fr::one()),
                   |lc| lc + sum_inv.get_variable(),
                   |lc| lc + bit.get_variable(),
        );


        Ok(Boolean::Is(bit))
    }

    pub fn assignment_not_leq_fixed<CS>(&self, mut cs: CS, namespace: &str, left_bits: &Vec<Boolean>, value: E::Fr, mut num_bits: usize) -> Result<Boolean, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let value: Vec<bool> = {
            let mut res = vec![];
            let mut value = value.into_repr();

            for _i in 0..num_bits {
                res.push(value.is_odd());
                value.div2();
            }

            res
        };

        while num_bits > 0 && !value[num_bits - 1] {
            num_bits -= 1;
        }

        if num_bits == 0 {
            return Ok(Boolean::Constant(true));
//            return Err(SynthesisError::Unsatisfiable);
        }

        let num_bits = num_bits;
        let left_bits = left_bits;

        assert!(left_bits.len() >= num_bits);

        let mut pi = Boolean::Constant(true);
        let mut e_arr = vec![];

        let mut sum: Num<E> = Num::zero();

        for i in (0..num_bits).rev() {
            if value[i] {
                pi = Boolean::and(cs.namespace(|| format!("{}: calc pi_i: {}", namespace, i)), &left_bits[i], &pi)?.not();
            } else {
                let e = Boolean::and(cs.namespace(|| format!("{}: calc e_i: {}", namespace, i)), &pi.not(), &left_bits[i])?.not();
                sum = sum.add_bool_with_coeff(CS::one(), &e, E::Fr::one());
                e_arr.push(e);
            }
        }

        let bit = {
            let b_val: Option<bool> = {
                let calc = || {
                    for bit in e_arr.as_slice() {
                        if let Some(e) = bit.get_value() {
                            if e {
                                return Some(true);
                            }
                        } else {
                            return None;
                        }
                    }

                    return Some(false);
                };

                calc()
            };

            AllocatedBit::alloc(cs.namespace(|| format!("{} allocate bit", namespace)),
                                b_val,
            )?
        };

        let sum_inv = AllocatedNum::alloc(cs.namespace(|| namespace.to_owned() + ": sum inv"), || {
            if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                let sum_val = sum.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                return sum_val.inverse().ok_or(SynthesisError::DivisionByZero);
            } else {
                return Ok(E::Fr::one());
            }
        })?;

        sum_inv.assert_nonzero(cs.namespace(|| namespace.to_owned() + "assert sum_inv non-zero"))?;

        cs.enforce(|| namespace.to_owned() + "assert b correct",
                   |_| sum.lc(E::Fr::one()),
                   |lc| lc + sum_inv.get_variable(),
                   |lc| lc + bit.get_variable(),
        );


        Ok(Boolean::Is(bit))
    }

    pub fn crh<CS>(&self, mut cs: CS, namespace: &str, bits: &[Boolean]) -> Result<AllocatedNum<E>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let cm: EdwardsPoint<E> = pedersen_hash(
            cs.namespace(|| namespace.to_owned() + "compute hash"),
            Personalization::NoteCommitment,
            bits,
            self.constants.jubjub,
        )?;

        Ok(cm.get_x().clone())
    }

    pub fn sub_binomial_regular<CS>(&self, mut cs: CS, namespace: &str, idx: usize, rand_bits: &Vec<Boolean>) -> Result<Num<E>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let mut num: Num<E> = Num::zero();
        let b_one = Boolean::Constant(true);
        num = num.add_bool_with_coeff(CS::one(), &b_one, self.constants.binomial.1[idx].clone());

        for i in 0..self.constants.binomial.0[idx].len() {
            let mut c = self.constants.binomial.0[idx][i].clone();
            c.sub_assign(&E::Fr::one());
            let bit = self.assignment_not_leq_fixed(cs.namespace(|| format!("{}: {} comparison # {}", namespace, idx, i)), format!("{}: {} comparison # {}", namespace, idx, i).as_ref(), rand_bits, c, 80)?;
            num = num.add_bool_with_coeff(CS::one(), &bit, E::Fr::one());
        }

        Ok(num)
    }

    pub fn sub_binomial_binary_search<CS>(&self, mut cs: CS, namespace: &str, idx: usize, rand_bits: &Vec<Boolean>) -> Result<Num<E>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let log_num_values = {
            let num_binom_values = (self.constants.binomial.0[idx].len() + 1) as f64;
            num_binom_values.log2() as usize
        };

        let constants = {
            let mut constants = self.constants.binomial.0[idx].clone();

            for i in 0..constants.len() {
                constants[i].sub_assign(&E::Fr::one());
            }


            while constants.len() != (2 << log_num_values) - 1 {
                let mut a = E::Fr::one();
                a.negate();
                constants.push(a);
            }

            constants
        };

        let mut covered = vec![];
        for _i in 0..((2 << log_num_values) - 1) {
            covered.push(false);
        }

        let mut bits: Vec<Boolean> = vec![];

        let list_list_start = {
            let mut list_list_start = vec![];
            for step in 0..log_num_values {
                let list_start = {
                    let mut list = vec![];
                    for i in 1..(1 + constants.len()) {
                        if (i & (2 << step) != 0) && !covered[i - 1] {
                            covered[i - 1] = true;
                            list.push(i - 1);
                        }
                    }

                    list
                };

                list_list_start.push(list_start);
            }

            list_list_start
        };

        for step in (0..log_num_values).rev() {
            let list_start = list_list_start[step].clone();

            //first round should be different
            if step == log_num_values - 1 {
                let bit = self.assignment_not_leq_fixed(cs.namespace(|| format!("{}: first bit comparision", namespace)), format!("{}: first bit comparision", namespace).as_ref(), rand_bits, constants[list_start[0]], 80)?;
                bits.push(bit);
                continue;
            }

            let mut list_num = {
                let mut list = vec![];
                for i in list_start {
                    let mut num = Num::<E>::zero();
                    num = num.add_bool_with_coeff(CS::one(), &Boolean::Constant(true), constants[i]);
                    list.push(num);
                }

                list
            };


            let mut count = 0;

            for bit in bits.iter().rev() {
                let mut new_list_num = vec![];

                for i in 0..list_num.len() {
                    //have not learned how to do skipping for loops yet oops
                    if i % 2 == 1 { continue; }

                    count = count + 1;

                    let n0 = &list_num[i];
                    let n1 = &list_num[i + 1];

                    let namespace2 = format!("{}: advanced binomial sampling {} {} {}", namespace, i, step, count);


                    let selected = AllocatedNum::alloc(cs.namespace(|| namespace2), || {
                        if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                            return n1.get_value().ok_or(SynthesisError::AssignmentMissing);
                        } else { return n0.get_value().ok_or(SynthesisError::AssignmentMissing); }
                    })?;

                    let constraint = format!("{}: advanced binomial sampling constraint {} {} {}", namespace, i, step, count);

                    let mut mone = E::Fr::one();
                    mone.negate();

                    cs.enforce(|| constraint,
                               |_| n1.lc(E::Fr::one()) - &n0.lc(E::Fr::one()),
                               |_| bit.lc(CS::one(), E::Fr::one()),
                               |_| n0.lc(mone) + selected.get_variable());

                    new_list_num.push(Num::from(selected));
                }

                list_num = new_list_num;
            }
            let num = &list_num[0];
            //finally have the selected constant

            let value = num.get_value();
            let values = match value {
                Some(value) => {
                    let mut value = value.into_repr();
                    let mut tmp = Vec::with_capacity(80);

                    for _i in 0..80 {
                        tmp.push(Some(value.is_odd()));
                        value.div2();
                    }

                    tmp
                }
                None => vec![None; 80],
            };

            let right_bits = values
                .into_iter()
                .enumerate()
                .map(|(i, b)| {
                    Ok(Boolean::from(AllocatedBit::alloc(
                        cs.namespace(|| format!("{} {} bit {}", namespace, step, i)),
                        b,
                    )?))
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?;

            let mut value_num = Num::zero();
            let mut coeff = E::Fr::one();
            for bit in &right_bits {
                value_num = value_num.add_bool_with_coeff(CS::one(), bit, coeff);
                coeff.double();
            }

            cs.enforce(|| format!("{} make sure that bits are of correct selected value {}", namespace, step),
                       |_| value_num.lc(E::Fr::one()),
                       |lc| lc + CS::one(),
                       |_| num.lc(E::Fr::one()));

            //assignment_not_leq_not_fixed<CS>(&self, mut cs: CS, namespace: &str, left_bits: &Vec<Boolean>, right_bits: &Vec<Boolean>)
            let new_bit = self.assignment_not_leq_not_fixed(cs.namespace(|| format!("{}{} actual comparision", namespace, step)), format!("{}{} actual comparision", namespace, step).as_ref(), &rand_bits, &right_bits)?;
            bits.push(new_bit);
        }

        let mut num = Num::zero();
        let mut coeff = E::Fr::one();

        for bit in bits.iter().rev() {
            num = num.add_bool_with_coeff(CS::one(), &bit, coeff);
            coeff.double();
        }

        Ok(num)
    }

    pub fn calc_num_selections<CS>(&self, mut cs: CS, namespace: &str, value_bits: &[Boolean], hash: &AllocatedNum<E>, a_sk: &AllocatedNum<E>) -> Result<AllocatedNum<E>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        let random_bits = {
            let mut random_bits = vec![];

            //screw it, hardcoded for num
            let num_prfs: usize = 20;
            let mut rand_values = vec![];
            for i in 0..num_prfs {
                let namespace2 = || format!("{}: mimc prf {}", namespace, i);
                let random = self.mimc_prf(cs.namespace(namespace2), namespace2().as_ref(), a_sk.clone(), hash.clone(), &self.constants.mimc.prf_sel[i])?;
                rand_values.push(random);
            }

            for i in 0..20 {
                let rand = &rand_values[i];
                let bits = rand.to_bits_le_strict(cs.namespace(|| format!("{}: get random val bits {}", namespace, i)))?;

                let mut b1 = vec![];
                let mut b2 = vec![];
                let mut b3 = vec![];

                b1.extend_from_slice(&bits[0..80]);
                b2.extend_from_slice(&bits[80..160]);
                b3.extend_from_slice(&bits[160..240]);

                random_bits.push(b1);
                random_bits.push(b2);
                random_bits.push(b3);
            }

            random_bits
        };

        let mut nums = vec![];

        for i in 0..60 {
            let num_binom_values = self.constants.binomial.0[i].len();
            if num_binom_values == 0 {
                continue;
            }

            let log_num_values = {
                let num_binom_values = (num_binom_values + 1) as f64;
                num_binom_values.log2() as usize
            };

            let calc_constraints_regular = 163 * num_binom_values;
            let calc_constraints_advanced = (2 << log_num_values) + 403 * log_num_values - 241;

            let num =
                if calc_constraints_regular < calc_constraints_advanced {
                    self.sub_binomial_regular(cs.namespace(|| format!("{}: sub binomial {}", namespace, i)), format!("{}: sub binomial {}", namespace, i).as_ref(), i, random_bits[i].as_ref())?
                } else {
                    self.sub_binomial_binary_search(cs.namespace(|| format!("{}: sub binomial {}", namespace, i)), format!("{}: sub binomial {}", namespace, i).as_ref(), i, random_bits[i].as_ref())?
                };

            let num2 = AllocatedNum::alloc(cs.namespace(|| format!("{}: allocate result {}", namespace, i)), || {
                if value_bits[i].get_value().ok_or(SynthesisError::AssignmentMissing)? {
                    Ok(num.get_value().ok_or(SynthesisError::AssignmentMissing)?)
                } else {
                    Ok(E::Fr::zero())
                }
            })?;

            cs.enforce(|| format!("constrain j_{} to 0 if bit is not set properly", i),
                       |_| num.lc(E::Fr::one()),
                       |_| value_bits[i].lc(CS::one(), E::Fr::one()),
                       |lc| lc + num2.get_variable(),
            );

            nums.push(num2);
        }

        let num_selected = AllocatedNum::alloc(cs.namespace(|| format!("{}: allocate j", namespace)), || {
            let mut val = E::Fr::zero();
            for num in nums.as_slice() {
                let num = num.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                val.add_assign(&num);
            }
            Ok(val)
        })?;

        let mut lc = LinearCombination::<E>::zero();
        for num in nums.as_slice() {
            lc = lc + num.get_variable();
        }

        cs.enforce(|| "calculation of j",
                   |_| lc,
                   |lc| lc + CS::one(),
                   |lc| lc + num_selected.get_variable());


        Ok(num_selected)
    }
}




