use std::io::Cursor;
use std::marker::PhantomData;
use std::time::Instant;

use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};

use constants::poseidon_constants::PoseidonConstants;
use edwards::Point;
use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use pairing::bls12_381::Bls12;
use poseidon::poseidon_hash;
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams, PrimeOrder, ToUniform};
use zcash_primitives::redjubjub;
use zcash_primitives::sapling::merkle_hash;

pub mod constants;
pub mod poseidon;

pub struct Constants<E: JubjubEngine> {
    pub jubjub: E::Params,
    pub poseidon: PoseidonConstants<E>,
}

/*
technically not a signature scheme because "signatures" reveal secret key
and only one kind of message can be "signed"

but in a zk-SNARK, we will have access to the secret key anyway
and only one type of message needs to be "signed" anyway (in this case, message = 0)

scheme: https://cseweb.ucsd.edu/~daniele/papers/MMM.pdf
*/
pub trait ForwardSecureSignatureScheme {
    type E: JubjubEngine;
    type SK;
    type PK;
    type Sig;

    fn key_gen(constants: &Constants<Self::E>, r: &[u8; 32]) -> (Self::SK, Self::PK) where Self::E: JubjubEngine + ScalarEngine;
    //note: updates to time t, not update at time t like in paper
    fn update(constants: &Constants<Self::E>, t: usize, sk: Self::SK) -> Self::SK where Self::E: JubjubEngine + ScalarEngine;
    fn sign(constants: &Constants<Self::E>, t: usize, sk: &Self::SK, m: &<Self::E as ScalarEngine>::Fr) -> Self::Sig where Self::E: JubjubEngine + ScalarEngine;
    fn verify(constants: &Constants<Self::E>, pk: &Self::PK, m: &<Self::E as ScalarEngine>::Fr, sig: &Self::Sig, t: usize) -> bool where Self::E: JubjubEngine + ScalarEngine;

    fn depth() -> u8;
    fn time_limit() -> usize;

    fn clone_sk(sk: &Self::SK) -> Self::SK;
    fn clone_sig(sig: &Self::Sig) -> Self::Sig;
    fn clone_pk(pk: &Self::PK) -> Self::PK;
    fn pk_to_field(pk: &Self::PK) -> <Self::E as ScalarEngine>::Fr where Self::E: JubjubEngine + ScalarEngine;
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

fn to_field<E: JubjubEngine>(input: &[u8]) -> E::Fs {
    let mut a = E::Fs::zero().into_repr();
    println!("failing in to_field?");
    a.read_be(Cursor::new(input)).unwrap();

    return E::Fs::from_repr(a).unwrap();
}

fn mod_merkle_hash(input: &[u8], m: &<Bls12 as ScalarEngine>::Fr) -> <<Bls12 as ScalarEngine>::Fr as PrimeField>::Repr {
    type Field = <Bls12 as ScalarEngine>::Fr;

    let mut a = <Field as PrimeField>::Repr::from(0);
    a.read_be(Cursor::new(input)).unwrap();
    let b = m.into_repr();

    return merkle_hash(0, &a, &b);
}

fn field_to_vec_u8<Fr: PrimeField>(field_elem: &Fr) -> Vec<u8> {
    let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    field_elem.into_repr().write_be(cursor.get_mut()).unwrap();
    return cursor.into_inner();
}


struct BasicSig<E: JubjubEngine> {
    phantom: PhantomData<E>
}

impl<Engine: JubjubEngine + ScalarEngine> ForwardSecureSignatureScheme for BasicSig<Engine> {
    type E = Engine;
    type SK = redjubjub::PrivateKey<Self::E>;
    type PK = redjubjub::PublicKey<Self::E>;
    type Sig = redjubjub::Signature;

    fn depth() -> u8 {
        return 1;
    }

    fn key_gen(constants: &Constants<Self::E>, r: &[u8; 32]) -> (Self::SK, Self::PK) {
        let sk1 = sha256_hash(r, &[Self::depth(), 0]);
        let sk2 = sha256_hash(r, &[Self::depth(), 1]);
        let mut sk = [0; 64];
        for i in 0..32 {
            sk[i] = sk1[i];
            sk[i + 32] = sk2[i];
        }

        let sk = <Self::E as JubjubEngine>::Fs::to_uniform(&sk);
        let sk = redjubjub::PrivateKey(sk);
        let pk = redjubjub::PublicKey::from_private(&sk, FixedGenerators::SpendingKeyGenerator, &constants.jubjub);

        return (sk, pk);
    }

    //    ignore cases where t >= 1
//    https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
    fn sign(constants: &Constants<Self::E>, t: usize, sk: &Self::SK, m: &<Self::E as ScalarEngine>::Fr) -> Self::Sig {
        assert_eq!(t, 0);

        let m = field_to_vec_u8(m);
        let sig = sk.sign(m.as_slice(), &mut thread_rng(), FixedGenerators::SpendingKeyGenerator, &constants.jubjub);
        let pk = redjubjub::PublicKey::from_private(&sk, FixedGenerators::SpendingKeyGenerator, &constants.jubjub);

        return sig;
    }

    fn update(constants: &Constants<Self::E>, t: usize, sk: Self::SK) -> Self::SK {
        if t == 0 {
            return sk;
        } else {
            return redjubjub::PrivateKey(<Self::E as JubjubEngine>::Fs::zero());
        }
    }

    fn verify(constants: &Constants<Self::E>, pk: &Self::PK, m: &<Self::E as ScalarEngine>::Fr, sig: &Self::Sig, t: usize) -> bool {
        if t == 1 {
            return false;
        }

        let m = field_to_vec_u8(m);

        return pk.verify(m.as_slice(), &sig, FixedGenerators::SpendingKeyGenerator, &constants.jubjub);
    }

    fn time_limit() -> usize {
        return 1;
    }

    fn clone_sk(sk: &Self::SK) -> Self::SK {
        return redjubjub::PrivateKey(sk.0.clone());
    }
    fn clone_sig(sig: &Self::Sig) -> Self::Sig {
        return sig.clone();
    }

    fn pk_to_field(pk: &Self::PK) -> <Self::E as ScalarEngine>::Fr {
        return pk.0.to_xy().0;
    }

    fn clone_pk(pk: &Self::PK) -> Self::PK {
        return redjubjub::PublicKey::<Self::E>(pk.0.clone());
    }
}

struct SumCompositionEight<B> {
    phantom: PhantomData<B>
}

impl<B> SumCompositionEight<B>
    where B: ForwardSecureSignatureScheme {

    fn hash_public_keys(constants: &Constants<B::E>, public_keys: &[B::PK; 8]) -> <B::E as ScalarEngine>::Fr {
        let mut public_key_xcoords: [<B::E as ScalarEngine>::Fr; 8] = [<B::E as ScalarEngine>::Fr::zero(); 8];
        for i in 0..8 {
            public_key_xcoords[i] = B::pk_to_field(&public_keys[i]);
        }

        return poseidon_hash(&constants.poseidon, &public_key_xcoords);
    }
}

impl<B> ForwardSecureSignatureScheme for SumCompositionEight<B>
    where B: ForwardSecureSignatureScheme, <B as ForwardSecureSignatureScheme>::E: ScalarEngine {
    type E = B::E;
    type SK = (B::SK, [[u8; 32]; 7], [B::PK; 8], usize);
    type PK = <Self::E as ScalarEngine>::Fr;
    type Sig = (B::Sig, [B::PK; 8]);

    fn depth() -> u8 {
        return B::depth() + 1;
    }

    fn key_gen(constants: &Constants<Self::E>, r: &[u8; 32]) -> (Self::SK, Self::PK)
        where Self::E: JubjubEngine + ScalarEngine {
        let random = {
            let mut random: [[u8; 32]; 8] = [[0; 32]; 8];
            random[0] = sha256_hash(r, &[Self::depth()]);
            for i in 1..8 {
                random[i] = sha256_hash(&random[i - 1], &[Self::depth()]);
            }

            random
        };

        let (sk_0, pk_0) = B::key_gen(constants, &random[0]);

        let public_keys = [pk_0, B::key_gen(constants, &random[1]).1,
            B::key_gen(constants, &random[2]).1, B::key_gen(constants, &random[3]).1,
            B::key_gen(constants, &random[4]).1, B::key_gen(constants, &random[5]).1,
            B::key_gen(constants, &random[6]).1, B::key_gen(constants, &random[7]).1];

        let pk = Self::hash_public_keys(constants, &public_keys);
        let sk: Self::SK = {
            let ret_random = [random[1], random[2], random[3], random[4], random[5], random[6], random[7]];
            (sk_0, ret_random, public_keys, 0)
        };

        return (sk, pk);
    }

    //will fail if t = 0
    fn update(constants: &Constants<Self::E>, t: usize, sk: Self::SK) -> Self::SK
        where Self::E: JubjubEngine + ScalarEngine {
        assert_ne!(t, 0);

        let t_last = t - (t % B::time_limit());
        let (mut sk, mut rand, pks, mut last_update) = sk;

        let i = t / B::time_limit();
        if i != 0 && i != last_update / B::time_limit() {
            let (sk_2, _) = B::key_gen(constants, &rand[i - 1]);
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

    fn sign(constants: &Constants<Self::E>, t: usize, sk: &Self::SK, m: &<Self::E as ScalarEngine>::Fr) -> Self::Sig
        where Self::E: JubjubEngine + ScalarEngine {
        let sig = B::sign(constants, t % B::time_limit(), &sk.0, m);

        let public_keys: [B::PK; 8] = [B::clone_pk(&sk.2[0]), B::clone_pk(&sk.2[1]),
            B::clone_pk(&sk.2[2]), B::clone_pk(&sk.2[3]),
            B::clone_pk(&sk.2[4]), B::clone_pk(&sk.2[5]),
            B::clone_pk(&sk.2[6]), B::clone_pk(&sk.2[7])];

        return (sig, public_keys);
    }

    fn verify(constants: &Constants<Self::E>, pk: &Self::PK, m: &<Self::E as ScalarEngine>::Fr, sig: &Self::Sig, t: usize) -> bool
        where Self::E: JubjubEngine + ScalarEngine {
        if Self::hash_public_keys(&constants, &sig.1) != *pk {
            return false;
        }

        let i = t / B::time_limit();
        return B::verify(constants, &sig.1[i], m, &sig.0, t % B::time_limit());
    }

    fn time_limit() -> usize {
        return 8 * B::time_limit();
    }

    fn clone_sk(sk: &Self::SK) -> Self::SK {
        unimplemented!()
//        return (B::clone_sk(&sk.0), sk.1.clone(), sk.2.clone(), sk.3);
    }

    fn clone_sig(sig: &Self::Sig) -> Self::Sig {
        unimplemented!()
//        return (B::clone_sig(&sig.0), sig.1.clone(), sig.2);
    }

    fn pk_to_field(pk: &Self::PK) -> <Self::E as ScalarEngine>::Fr {
        return pk.clone();
    }

    fn clone_pk(pk: &Self::PK) -> Self::PK {
        return pk.clone();
    }
}


struct MultiplyComposition<B> {
    phantom: PhantomData<B>
}

impl<B> ForwardSecureSignatureScheme for MultiplyComposition<B>
where B: ForwardSecureSignatureScheme {
    type E = B::E;
    type SK = (B::SK, B::Sig, B::SK, B::PK, [u8; 32], usize);
    type Sig = (B::PK, B::Sig, B::Sig);
    type PK = B::PK;

    fn depth() -> u8 {
        return B::depth() + 1;
    }

    fn key_gen(constants: &Constants<Self::E>, r: &[u8; 32]) -> (Self::SK, Self::PK) {
        let r_0 = sha256_hash(r, &[Self::depth(), 0]);
        let r_1 = sha256_hash(r, &[Self::depth(), 1]);
        let r1_p = sha256_hash(&r_1, &[Self::depth(), 0]);
        let r1_pp = sha256_hash(&r_1, &[Self::depth(), 1]);

        let (sk_0, pk) = B::key_gen(constants, &r_0);
        let (sk_1, pk_1) = B::key_gen(constants, &r1_p);
        let sigma = B::sign(constants, 0, &sk_0, &B::pk_to_field(&pk_1));
        let sk_0 = B::update(constants, 1, sk_0);

        let sk: Self::SK = (sk_0, sigma, sk_1, pk_1, r1_pp, 0);
        return (sk, pk);
    }

    fn update(constants: &Constants<Self::E>, t: usize, sk: Self::SK) -> Self::SK {
        let (mut sk_0, mut sigma, mut sk_1, mut pk_1, mut r, mut last_update) = sk;

        let a = last_update / B::time_limit();
        let b = t / B::time_limit();

        if a != b {
            let r_p = sha256_hash(&r, &[Self::depth(), 0]);
            r = sha256_hash(&r, &[Self::depth(), 1]);

            let tmp = B::key_gen(constants, &r_p);
            sk_1 = tmp.0;
            pk_1 = tmp.1;

            if a + 1 != b {
                sk_0 = B::update(constants, b, sk_0);
            }

            sigma = B::sign(constants, t / B::time_limit(), &sk_0, &B::pk_to_field(&pk_1));


            if 1 + b < B::time_limit() {
                sk_0 = B::update(constants, 1 + (t / B::time_limit()), sk_0);
            }


            last_update = t - (t % B::time_limit());
        }

        if t != last_update {
            sk_1 = B::update(constants, t % B::time_limit(), sk_1);
        }

        return (sk_0, sigma, sk_1, pk_1, r, t);
    }

    fn sign(constants: &Constants<Self::E>, t: usize, sk: &Self::SK, m: &<Self::E as ScalarEngine>::Fr) -> Self::Sig {
        let sigma_1 = B::sign(constants, t % B::time_limit(), &sk.2, m);
        return (B::clone_pk(&sk.3), B::clone_sig(&sk.1), sigma_1);
    }

    fn verify(constants: &Constants<Self::E>, pk: &Self::PK, m: &<Self::E as ScalarEngine>::Fr, sig: &Self::Sig, t: usize) -> bool {
        let v_0 = B::verify(constants, pk, &B::pk_to_field(&sig.0), &sig.1, t / B::time_limit());
        let v_1 = B::verify(constants, &sig.0, m, &sig.2, t % B::time_limit());
        return v_0 && v_1;
    }

    fn time_limit() -> usize {
        return B::time_limit() * B::time_limit();
    }

    fn clone_sk(sk: &Self::SK) -> Self::SK {
        return (B::clone_sk(&sk.0), B::clone_sig(&sk.1), B::clone_sk(&sk.2), B::clone_pk(&sk.3), sk.4, sk.5);
    }

    fn clone_sig(sig: &Self::Sig) -> Self::Sig {
        return (B::clone_pk(&sig.0), B::clone_sig(&sig.1), B::clone_sig(&sig.2));
    }

    fn clone_pk(pk: &Self::PK) -> Self::PK {
        unimplemented!()
    }

    fn pk_to_field(pk: &Self::PK) -> <Self::E as ScalarEngine>::Fr  {
        return B::pk_to_field(&pk);
    }
}



fn main() {
    let rng = &mut thread_rng();

    let constants = Constants {
        jubjub: JubjubBls12::new(),
        poseidon: PoseidonConstants::<Bls12>::get(),
    };

    type SigScheme = BasicSig<Bls12>;

    let rand: [u8; 32] = rng.gen();
    let (mut sk, pk) = SigScheme::key_gen(&constants, &rand);
    let sig = SigScheme::sign(&constants, 0, &sk, &<Bls12 as ScalarEngine>::Fr::zero());
    let result = SigScheme::verify(&constants, &pk, &<Bls12 as ScalarEngine>::Fr::zero(), &sig, 0);

    println!("result: {}", result);


//
//
//    type SigScheme = MultiplyComposition<MultiplyComposition<SumCompositionEight<SumCompositionEight<SumCompositionEight<BasicSig>>>>>;
//    type Field = <Bls12 as ScalarEngine>::Fr;
//    println!("log_2 (time periods) = {}", (SigScheme::time_limit() as f64).log2());
//
//    let start = Instant::now();
//    let mut now = Instant::now();
//
//    let rand: [u8; 32] = rng.gen();
//    let (mut sk, pk) = SigScheme::key_gen(&constants, rand);
//
//    println!("key gen time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
//    now = Instant::now();
//
//    let times = vec![1, 2, 5, 6, 9, 10, 11, 15, 20, 30, 45, 63, 1 << 9, (1 << 9) + 15, (1 << 9) + 26 + 14, (1 << 15) + 352, (1 << 30) + 368732535, (1 << 36) - 1, (1 << 36)];
//    let mut t: usize = 0;
//
//    let original = sk.2.clone();
//    for time in times {
//
//        println!("compute for time {}", t);
//        let sig = SigScheme::sign(&constants, t, sk, Field::zero());
//        println!("sign time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
//        now = Instant::now();
//
//        let verify = SigScheme::verify(&constants, pk, Field::zero(), sig, t);
//
//        println!("verify result: {}", verify);
//
//        if !verify {
//            break;
//        }
//
//        println!("verify time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
//        now = Instant::now();
//
//        t = time;
//        if t >= SigScheme::time_limit() {
//            break;
//        }
//
//        sk = SigScheme::update(&constants, t, sk);
//        println!("update time ==> since last time: {} | total time since start {}", now.elapsed().as_millis(), start.elapsed().as_millis());
//        now = Instant::now();
//
//        println!("\n\n");
//    }
}
