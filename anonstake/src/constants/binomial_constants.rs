use ff::ScalarEngine;

#[derive(Clone)]
pub enum TauValue {
    Tau20,
    Tau2000,
    Tau1500,
    Tau5000,
    Tau2990,
}

impl From<&TauValue> for &str {
    fn from(tau: &TauValue) -> Self {
        match tau {
            TauValue::Tau20 => "tau20",
            TauValue::Tau1500 => "tau1500",
            TauValue::Tau2000 => "tau2000",
            TauValue::Tau2990 => "tau2990",
            TauValue::Tau5000 => "tau5000"
        }
    }
}

pub struct BinomialConstants<E: ScalarEngine>(pub [Vec<E::Fr>; 60], pub [E::Fr; 60]);

