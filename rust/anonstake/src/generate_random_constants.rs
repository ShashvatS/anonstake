use rand::thread_rng;
use ff::{Field, PrimeField, ScalarEngine};
use pairing::bls12_381::Bls12;

use std::io;

fn main() {

    println!("Enter something to continue; this is anti-wall-of-text protection");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).expect("oh well, something went wrong");

    let rng = &mut thread_rng();
    for _j in 0..10 {
        for _i in 0..162 {
            let a = <Bls12 as ScalarEngine>::Fr::random(rng).into_repr();
            println!("{}", a);
        }
    }

}