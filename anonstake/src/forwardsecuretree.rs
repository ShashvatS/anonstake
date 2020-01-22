extern crate sha2;

use std::io::Cursor;
use std::slice;

use rand::thread_rng;
use sha2::{Digest, Sha256};

use constants::poseidon_constants::PoseidonConstants;
use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use pairing::bls12_381::Bls12;
use poseidon::poseidon_hash;
use zcash_primitives::sapling::merkle_hash;

use std::time::Instant;

mod poseidon;
mod constants;

pub fn increase(input: &mut [u8], times: usize) {
    for _i in 0..times {
        let mut hasher = Sha256::new();
        hasher.input(input.as_ref());
        hasher.input([0x02]);
        let result = hasher.result();

        for i in 0..input.len() {
            input[i] = result[i];
        }
    }
}

pub fn tree_leaves(base: <Bls12 as ScalarEngine>::Fr, num: usize) -> Vec<<<Bls12 as ScalarEngine>::Fr as PrimeField>::Repr> {
    type Field = <Bls12 as ScalarEngine>::Fr;

    let mut base_repr = base.into_repr();
    let base_repr: &mut [u64] = base_repr.as_mut();

    let cur: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(base_repr.as_ptr() as *mut u8, base_repr.len() * 8)
    };

    let mut ans = Vec::with_capacity(num);
    let mut role: u64 = 0;

    for _i in 0..num {
        increase(cur.as_mut(), 1);
        role += 1;

        let mut a: <Field as PrimeField>::Repr = Field::zero().into_repr();
        a.read_be(Cursor::new(cur.as_ref())).unwrap();
        let b = <Field as PrimeField>::Repr::from(role);

        let leaf = merkle_hash(0, &a, &b);

        ans.push(leaf);
    }

    return ans;
}

pub fn reduce(constants: &PoseidonConstants<Bls12>, elems: Vec<<<Bls12 as ScalarEngine>::Fr as PrimeField>::Repr>) -> <Bls12 as ScalarEngine>::Fr {
    type Fr = <Bls12 as ScalarEngine>::Fr;
    let mut cur: Vec<Fr> = Vec::with_capacity(elems.len());
    for i in 0..elems.len() {
        cur.push(Fr::from_repr(elems[i]).unwrap());
    }

    let now = Instant::now();
    while cur.len() != 1 {
        let mut next = Vec::with_capacity(cur.len() / 8);

        for i in 0..(cur.len() / 8) {
            next.push(poseidon_hash(constants, &cur[8 * i..8 * i + 8]));
        }

        cur = next;
    }

    return cur[0].clone();
}

pub fn compute_a_sk() {}

fn main() {
    let rng = &mut thread_rng();

    let base = <Bls12 as ScalarEngine>::Fr::random(rng);
    let base_repr = base.into_repr();

    let constants = PoseidonConstants::<Bls12>::get();

    let now = Instant::now();
    let leaves = tree_leaves(base, 1 << 15);
    println!("leaves {}", now.elapsed().as_millis());

    reduce(&constants, leaves);
    println!("reduce {}", now.elapsed().as_millis());
}


