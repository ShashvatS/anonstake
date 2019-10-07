#![feature(test)]
extern crate test;

use std::sync::Arc;
use std::time::Instant;

use rand::thread_rng;

use bellman::domain::{EvaluationDomain, Scalar};
use bellman::multicore::Worker;
use ff::{Field, PrimeField, ScalarEngine};
use pairing::bls12_381::Bls12;
use pairing::Engine;

fn single_fft<E: Engine + ScalarEngine>(mut a: EvaluationDomain<E, Scalar<E>>, mut b: EvaluationDomain<E, Scalar<E>>, mut c: EvaluationDomain<E, Scalar<E>>, worker: &Worker) -> Arc<Vec<<E::Fr as PrimeField>::Repr>> {
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
    return Arc::new(a.into_iter().map(|s| s.0.into_repr()).collect::<Vec<_>>());
}

fn generate_data<E: Engine>(num_proofs: usize, size: usize) -> Vec<(EvaluationDomain<E, Scalar<E>>, EvaluationDomain<E, Scalar<E>>, EvaluationDomain<E, Scalar<E>>)> {
    let rng = &mut thread_rng();

    let mut poly: Vec<Vec<Scalar<E>>> = vec![];
    for i in 0..3 * num_proofs {
        poly.push(vec![]);
        for _ in 0..size {
            let random: Scalar<E> = Scalar(E::Fr::random(rng));
            poly[i].push(random);
        }
    }

    let mut poly2: Vec<(EvaluationDomain<E, Scalar<E>>, EvaluationDomain<E, Scalar<E>>, EvaluationDomain<E, Scalar<E>>)> = vec![];
    for _ in 0..num_proofs {
        let mut iter = poly.drain(poly.len() - 3..);
        let a = EvaluationDomain::from_coeffs(iter.next().expect("rip1")).expect("rip2");
        let b = EvaluationDomain::from_coeffs(iter.next().expect("rip1")).expect("rip2");
        let c = EvaluationDomain::from_coeffs(iter.next().expect("rip1")).expect("rip2");

        poly2.push((a, b, c));
    }

    poly2
}

fn generate_data_and_run<E: Engine>(num_proofs: usize, size: usize) {
    let worker = Worker::new();
    let poly = generate_data::<E>(num_proofs, size);

    for (a, b, c) in poly {
        let _res = single_fft(a, b, c, &worker);
    }
}

fn run_fft<E: Engine>(poly: Vec<(EvaluationDomain<E, Scalar<E>>, EvaluationDomain<E, Scalar<E>>, EvaluationDomain<E, Scalar<E>>)>) {
    let worker = Worker::new();
    for (a, b, c) in poly {
        let _res = single_fft(a, b, c, &worker);
    }
}

fn main() {
    println!("Hello, world!");
    let data = generate_data::<Bls12>(12, 1<<17);

    let now = Instant::now();
    run_fft::<Bls12>(data);
    println!("{}", now.elapsed().as_millis());
}


#[cfg(test)]
mod tests {
    use test::Bencher;

    use super::*;

    #[bench]
    fn bench_minus_two(b: &mut Bencher) {
        //let data = generate_data::<Bls12>(12, 1<<17);
        b.iter(|| generate_data_and_run::<Bls12>(12, 1<<17));
    }
}
