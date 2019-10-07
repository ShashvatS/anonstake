use pairing::Engine;
use pairing::bls12_381::Bls12;
use bellman::domain::{EvaluationDomain, Scalar, Group};
use rand_core::RngCore;
use rand::thread_rng;
use ff::{Field, PrimeField, ScalarEngine};
use bellman::multicore::Worker;
use std::sync::Arc;

fn benchmark_fft<E: Engine>(num_proofs: usize, size: usize) {
    let rng = &mut thread_rng();
    let worker = Worker::new();

    let mut poly: Vec<Vec<Scalar<E>>> = vec![];
    for i in 0..3 * num_proofs {
        poly.push(vec![]);
        for _ in 0..size {
            let random: Scalar<E> = Scalar(E::Fr::random(rng));
            poly[i].push(random);
        }
    }

    let poly = {
        let mut poly2: Vec<(Vec<Scalar<E>>, Vec<Scalar<E>>, Vec<Scalar<E>>)> = vec![];
        for _ in 0..num_proofs {
            let mut iter = poly.drain(poly.len() - 3..);
            let (a, b, c) = (iter.next().expect("wtf"), iter.next().expect("wtf"), iter.next().expect("wtf"));
            poly2.push((a, b, c));
        }

        poly2
    };

    for (poly_a, poly_b, poly_c) in poly {
        let mut a = EvaluationDomain::from_coeffs(poly_a).expect("big rip");
        let mut b = EvaluationDomain::from_coeffs(poly_b).expect("big rip");
        let mut c = EvaluationDomain::from_coeffs(poly_c).expect("big rip");
        a.ifft(&worker);
        a.coset_fft(&worker);
        b.ifft(&worker);
        b.coset_fft(&worker);
        c.ifft(&worker);
        c.coset_fft(&worker);

        a.mul_assign(&worker, &b);
        drop(b);
        a.sub_assign(&worker, &c);
        drop(c);
        a.divide_by_z_on_coset(&worker);
        a.icoset_fft(&worker);
        let mut a = a.into_coeffs();
        let a_len = a.len() - 1;
        a.truncate(a_len);
        // TODO: parallelize if it's even helpful
        let _a = Arc::new(a.into_iter().map(|s| s.0.into_repr()).collect::<Vec<_>>());

    }

//    let poly = {
//        let res = (EvaluationDomain::from_coeffs(&poly[0].0), EvaluationDomain::from_coeffs(&poly[0].1), EvaluationDomain::from_coeffs(&poly[0].2));
//        let mut poly2 = vec![res];
//        for i in 1..num_proofs {
//            let res = (EvaluationDomain::from_coeffs(&poly[i].0), EvaluationDomain::from_coeffs(&poly[i].1), EvaluationDomain::from_coeffs(&poly[i].2));
//            poly2.push(res);
//        }
//
//        poly2
//    };

//    let poly = {
//        let trial: Vec<Scalar<E>> = &poly[0];
//        let trial = EvaluationDomain::from_coeffs(trial);
//        let vec = vec![(trial)];
//
//        vec
//    };

//    let mut poly = {
//        let mut poly2: Vec<(EvaluationDomain<E, dyn Group<E>>, EvaluationDomain<E, dyn Group<E>>, EvaluationDomain<E, dyn Group<E>>)> = vec![];
//        for i in 0..num_proofs {
//            let a = EvaluationDomain::from_coeffs(poly[3 * i]).expect("big rip");
//            let b = EvaluationDomain::from_coeffs(poly[3 * i + 1]).expect("big rip");
//            let c = EvaluationDomain::from_coeffs(poly[3 * i + 2]).expect("big rip");
//            poly2.push((a, b, c));
//        }
//
//        poly2
//    };

//    for (mut poly_a, mut poly_b, mut poly_c) in poly {
//        for &mut poly in [&mut poly_a, &mut poly_b, &mut poly_c] {
//            poly.ifft(&worker);
//        }
//    }


//    let mut a = EvaluationDomain::EvaluationDomain::from_coeffs(a).expect("big rip");
//    a.fft(&worker);
}

fn main() {
    println!("Hello, world!");
    let size: usize = 1 << 17;

    benchmark_fft::<Bls12>(12, size);
}
