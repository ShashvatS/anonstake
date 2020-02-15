use std::io::Cursor;
use std::marker::PhantomData;
use std::time::Instant;

use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};

use constants::poseidon_constants::PoseidonConstants;
use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use pairing::bls12_381::Bls12;
use poseidon::poseidon_hash;
use zcash_primitives::sapling::merkle_hash;

pub mod constants;
pub mod poseidon;

/*
technically not a sigature scheme because "signatures" reveal secret key
and only one kind of message can be "signed"

but in a zk-SNARK, we will have access to the secret key anyway
and only one type of message needs to be "signed" anyway (in this case, message = 0)

scheme: https://cseweb.ucsd.edu/~daniele/papers/MMM.pdf
*/
pub trait ForwardSecureSignatureScheme {
    type SK;
    type Sig;

    fn key_gen(constants: &PoseidonConstants<Bls12>, r: [u8; 32]) -> (Self::SK, <Bls12 as ScalarEngine>::Fr);
    //note: updates to time t, not update at time t like in paper
    fn update(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK) -> Self::SK;
    fn sign(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK, m: <Bls12 as ScalarEngine>::Fr) -> Self::Sig;
    fn verify(constants: &PoseidonConstants<Bls12>, pk: <Bls12 as ScalarEngine>::Fr, m: <Bls12 as ScalarEngine>::Fr, sig: Self::Sig, t: usize) -> bool;

    fn depth() -> u8;
    fn time_limit() -> usize;

    fn clone_sk(sk: &Self::SK) -> Self::SK;
    fn clone_sig(sig: &Self::Sig) -> Self::Sig;
}

fn sha256_hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(&a);
    hasher.input(b);
    let result = hasher.result();

    let mut res: [u8; 32] = [0; 32];
    for i in 0..32 {
        res[i] = result[i];
    }

    return res;
}

fn mod_merkle_hash(input: &[u8], m: &<Bls12 as ScalarEngine>::Fr) -> <<Bls12 as ScalarEngine>::Fr as PrimeField>::Repr {
    type Field = <Bls12 as ScalarEngine>::Fr;

    let mut a = <Field as PrimeField>::Repr::from(0);
    a.read_be(Cursor::new(input)).unwrap();
    let b = m.into_repr();

    return merkle_hash(0, &a, &b);
}

struct BasicSig;

impl ForwardSecureSignatureScheme for BasicSig {
    type SK = [u8; 32];
    type Sig = (Self::SK, <Bls12 as ScalarEngine>::Fr, usize);

    fn depth() -> u8 {
        return 1;
    }

    //ignore cases where t >= 1
    fn sign(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK, m: <Bls12 as ScalarEngine>::Fr) -> Self::Sig {
//        println!("sign: {}", m);
        let sig = mod_merkle_hash(&sk, &m);
        return (sk, <Bls12 as ScalarEngine>::Fr::from_repr(sig).unwrap(), t);
    }

    fn key_gen(constants: &PoseidonConstants<Bls12>, r: [u8; 32]) -> (Self::SK, <Bls12 as ScalarEngine>::Fr) {
        let sk = sha256_hash(&r, &[Self::depth()]);
        let pk = mod_merkle_hash(&sk, &<Bls12 as ScalarEngine>::Fr::zero());
        return (sk, <Bls12 as ScalarEngine>::Fr::from_repr(pk).unwrap());
    }

    fn update(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK) -> Self::SK {
        if t == 0 {
            return sk;
        } else {
            return [0; 32];
        }
    }

    fn verify(constants: &PoseidonConstants<Bls12>, pk: <Bls12 as ScalarEngine>::Fr, m: <Bls12 as ScalarEngine>::Fr, sig: Self::Sig, t: usize) -> bool {
        let sig2 = mod_merkle_hash(&sig.0, &m);
        let pk2 = mod_merkle_hash(&sig.0, &<Bls12 as ScalarEngine>::Fr::zero());

        return sig.1.into_repr() == sig2 && pk.into_repr() == pk2;
    }

    fn time_limit() -> usize {
        return 1;
    }

    fn clone_sk(sk: &Self::SK) -> Self::SK {
        let mut ret: [u8; 32] = [0; 32];
        for i in 0..32 {
            ret[i] = sk[i];
        }
        return ret;
    }
    fn clone_sig(sig: &Self::Sig) -> Self::Sig {
        return (Self::clone_sk(&sig.0), sig.1.clone(), sig.2);
    }

}

struct SumCompositionEight<B> {
    phantom: PhantomData<B>
}

impl<B> ForwardSecureSignatureScheme for SumCompositionEight<B>
    where B: ForwardSecureSignatureScheme {
    type SK = (B::SK, [[u8; 32]; 7], [<Bls12 as ScalarEngine>::Fr; 8], usize);
    type Sig = (B::Sig, [<Bls12 as ScalarEngine>::Fr; 8], usize);

    fn depth() -> u8 {
        return B::depth() + 1;
    }

    fn key_gen(constants: &PoseidonConstants<Bls12>, r: [u8; 32]) -> (Self::SK, <Bls12 as ScalarEngine>::Fr) {
        let random = {
            let mut random: [[u8; 32]; 8] = [[0; 32]; 8];
            random[0] = sha256_hash(&r, &[Self::depth()]);
            for i in 1..8 {
                random[i] = sha256_hash(&random[i - 1], &[Self::depth()]);
            }

            random
        };

        let (sk_0, pk_0) = B::key_gen(constants, random[0]);

        let mut pks: [<Bls12 as ScalarEngine>::Fr; 8] = [<Bls12 as ScalarEngine>::Fr::zero(); 8];
        pks[0] = pk_0;

        for i in 1..8 {
            let (_, pk) = B::key_gen(constants, random[i].clone());
            pks[i] = pk;
        }

        let pks = pks;

        let ret_random = [random[1], random[2], random[3], random[4], random[5], random[6], random[7]];

        let sk: Self::SK = (sk_0, ret_random, pks, 0);

        let pk = poseidon_hash(constants, &pks);

        return (sk, pk);
    }

    //will fail if t = 0
    fn update(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK) -> Self::SK {
//        if t > Self::time_limit() {
//            return ([0; 32], [[0; 32]; 7], [<Bls12 as ScalarEngine>::Fr::zero(); 8]; t);
//        }

        let t_last = t - (t % B::time_limit());
        let (mut sk, mut rand, pks, mut last_update) = sk;

        let i = t / B::time_limit();
        if i != 0 && i != last_update / B::time_limit() {
            let (sk_2, _) = B::key_gen(constants, rand[i - 1].clone());
            sk = sk_2;
        }

        for j in (last_update / B::time_limit())..i {
            rand[j] = [0; 32];
        }

        last_update = t_last;

        if t_last == t {
            return (sk, rand, pks, last_update);
        }

        let sk = B::update(constants, t - t_last, sk);
        return (sk, rand, pks, last_update);
    }

    fn sign(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK, m: <Bls12 as ScalarEngine>::Fr) -> Self::Sig {
        let sig = B::sign(constants, t % B::time_limit(), sk.0, m);
        return (sig, sk.2.clone(), t);
    }

    fn verify(constants: &PoseidonConstants<Bls12>, pk: <Bls12 as ScalarEngine>::Fr, m: <Bls12 as ScalarEngine>::Fr, sig: Self::Sig, t: usize) -> bool {
        if poseidon_hash(constants, &sig.1) != pk {
            return false;
        }

        let i = t / B::time_limit();


        return B::verify(constants, sig.1[i].clone(), m, sig.0, t % B::time_limit());
    }

    fn time_limit() -> usize {
        return 8 * B::time_limit();
    }

    fn clone_sk(sk: &Self::SK) -> Self::SK {
        return (B::clone_sk(&sk.0), sk.1.clone(), sk.2.clone(), sk.3);
    }

    fn clone_sig(sig: &Self::Sig) -> Self::Sig {
        return (B::clone_sig(&sig.0), sig.1.clone(), sig.2);
    }
}

struct MultiplyComposition<B> {
    phantom: PhantomData<B>
}

impl<B> ForwardSecureSignatureScheme for MultiplyComposition<B>
where B: ForwardSecureSignatureScheme {
    type SK = (B::SK, B::Sig, B::SK, <Bls12 as ScalarEngine>::Fr, [u8; 32], usize);
    type Sig = (<Bls12 as ScalarEngine>::Fr, B::Sig, B::Sig, usize);

    fn depth() -> u8 {
        return B::depth() + 1;
    }

    fn key_gen(constants: &PoseidonConstants<Bls12>, r: [u8; 32]) -> (Self::SK, <Bls12 as ScalarEngine>::Fr) {
        let r_0 = sha256_hash(&r, &[Self::depth(), 0]);
        let r_1 = sha256_hash(&r, &[Self::depth(), 1]);
        let r1_p = sha256_hash(&r_1, &[Self::depth(), 0]);
        let r1_pp = sha256_hash(&r_1, &[Self::depth(), 1]);

        let (sk_0, pk) = B::key_gen(constants, r_0.clone());
        let (sk_1, pk_1) = B::key_gen(constants, r1_p);
        let sigma = B::sign(constants, 0, B::clone_sk(&sk_0), pk_1.clone());
        let sk_0 = B::update(constants, 1, sk_0);

        let sk = (sk_0, sigma, sk_1, pk_1, r1_pp, 0);
        return (sk, pk);
    }

    fn update(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK) -> Self::SK {
//        dealing with cleaning up at the end is very annoying
//        if t > Self::time_limit() {
//            return [0; 32];
//        }

        let (mut sk_0, mut sigma, mut sk_1, mut pk_1, mut r, mut last_update) = sk;

        let a = last_update / B::time_limit();
        let b = t / B::time_limit();

        if a != b {
            let r_p = sha256_hash(&r, &[Self::depth(), 0]);
            r = sha256_hash(&r, &[Self::depth(), 1]);

            let tmp = B::key_gen(constants, r_p);
            sk_1 = tmp.0;
            pk_1 = tmp.1;

            if a + 1 != b {
                sk_0 = B::update(constants, b, sk_0);
            }

            sigma = B::sign(constants, t / B::time_limit(), B::clone_sk(&sk_0), pk_1.clone());


            if 1 + b < B::time_limit() {
                sk_0 = B::update(constants, 1 + (t / B::time_limit()), sk_0);
            }

            // dealing with clearing out sk_0 is very annoying
//
//            else {
//                sk_0 = B::update(constants, B::time_limit(), sk_0);
//                sk_1 = B::update(constants, B::time_limit(), sk_1);
//            }



            last_update = t - (t % B::time_limit());
        }

        if t != last_update {
            sk_1 = B::update(constants, t % B::time_limit(), sk_1);
        }

        return (sk_0, sigma, sk_1, pk_1, r, t);
    }

    fn sign(constants: &PoseidonConstants<Bls12>, t: usize, sk: Self::SK, m: <Bls12 as ScalarEngine>::Fr) -> Self::Sig {
        let sigma_1 = B::sign(constants, t % B::time_limit(), sk.2, m);
        return (sk.3, sk.1, sigma_1, t);
    }

    fn verify(constants: &PoseidonConstants<Bls12>, pk: <Bls12 as ScalarEngine>::Fr, m: <Bls12 as ScalarEngine>::Fr, sig: Self::Sig, t: usize) -> bool {
        let v_0 = B::verify(constants, pk, sig.0.clone(), sig.1, t / B::time_limit());
        let v_1 = B::verify(constants, sig.0, m, sig.2, t % B::time_limit());
        return v_0 && v_1;
    }

    fn time_limit() -> usize {
        return B::time_limit() * B::time_limit();
    }

    fn clone_sk(sk: &Self::SK) -> Self::SK {
        return (B::clone_sk(&sk.0), B::clone_sig(&sk.1), B::clone_sk(&sk.2), sk.3.clone(), sk.4, sk.5);
    }

    fn clone_sig(sig: &Self::Sig) -> Self::Sig {
        return (sig.0.clone(), B::clone_sig(&sig.1), B::clone_sig(&sig.2), sig.3);
    }
}

fn main() {
    let rng = &mut thread_rng();
    let constants = PoseidonConstants::<Bls12>::get();

    type SigScheme = MultiplyComposition<MultiplyComposition<SumCompositionEight<SumCompositionEight<SumCompositionEight<BasicSig>>>>>;
    type Field = <Bls12 as ScalarEngine>::Fr;
    println!("log_2 (time periods) = {}", (SigScheme::time_limit() as f64).log2());

    let start = Instant::now();
    let mut now = Instant::now();

    let rand: [u8; 32] = rng.gen();
    let (mut sk, pk) = SigScheme::key_gen(&constants, rand);

    println!("key gen time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
    now = Instant::now();

    let times = vec![1, 2, 5, 6, 9, 10, 11, 15, 20, 30, 45, 63, 1 << 9, (1 << 9) + 15, (1 << 9) + 26 + 14, (1 << 15) + 352, (1 << 30) + 368732535, (1 << 36) - 1, (1 << 36)];
    let mut t: usize = 0;

    let original = sk.2.clone();
    for time in times {

        println!("compute for time {}", t);
        let sig = SigScheme::sign(&constants, t, sk, Field::zero());
        println!("sign time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
        now = Instant::now();

        let verify = SigScheme::verify(&constants, pk, Field::zero(), sig, t);

        println!("verify result: {}", verify);

        if !verify {
            break;
        }

        println!("verify time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
        now = Instant::now();

        t = time;
        if t >= SigScheme::time_limit() {
            break;
        }

        sk = SigScheme::update(&constants, t, sk);
        println!("update time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
        now = Instant::now();

        println!("\n\n");
    }
}
