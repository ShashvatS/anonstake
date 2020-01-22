use super::constants::poseidon_constants::PoseidonConstants;
use ff::{Field, ScalarEngine};


pub fn poseidon_hash<E: ScalarEngine>(poseidon: &PoseidonConstants<E>, elems: &[E::Fr]) -> E::Fr {
    let mut state: [E::Fr; 9] = [E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero()];
    for i in 0..8 {
        state[i] = elems[i].clone();
    }

    for round in 0..poseidon.r_f + poseidon.r_p {
        if round < poseidon.r_f / 2 || round >= poseidon.r_p + poseidon.r_f / 2 {
            for i in 0..9 {
                state[i] = state[i].pow([5]);
            }
        } else {
            state[0] = state[0].pow([5]);
        }

        let mut output: [E::Fr; 9] = [E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero(), E::Fr::zero()];

        for i in 0..9 {
            for j in 0..9 {
                let mut tmp = state[j].clone();
                tmp.mul_assign(&poseidon.mds[i][j]);
                output[i].add_assign(&tmp);
            }
        }

        for i in 0..9 {
            state[i] = output[i];
        }
    }


    return state[0].clone();
}