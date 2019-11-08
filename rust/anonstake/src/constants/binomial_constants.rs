use ff::{PrimeField, ScalarEngine};

#[derive(Clone)]
pub enum TauValue {
    Tau20,
    Tau2000,
    Tau1500,
    Tau5000,
    Tau2990,
}

pub struct BinomialConstants<E: ScalarEngine>(pub [Vec<E::Fr>; 60], pub [E::Fr; 60]);

