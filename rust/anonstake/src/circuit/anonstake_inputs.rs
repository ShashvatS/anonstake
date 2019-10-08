use zcash_primitives::jubjub::JubjubEngine;

pub struct PubInput<E: JubjubEngine> {
    pub root_cm: Option<E::Fr>,
    pub root_sn: Option<E::Fr>,
    pub tsn: Option<E::Fr>,
    pub role: Option<E::Fr>,
    pub seed: Option<E::Fr>,
    pub h: Option<E::Fr>,
    pub h_sig: Option<E::Fr>
}

pub struct Coin<E: JubjubEngine> {
    pub a_pk: Option<E::Fr>,
    pub value: Option<u64>,
    pub rho: Option<E::Fr>,
    pub s: Option<E::Fs>
}

pub struct AuxInput<E: JubjubEngine> {
    pub cm_merkle_path: Vec<Option<(E::Fr, bool)>>,
    pub coin: Coin<E>,
    pub a_sk: Option<E::Fr>
}

pub struct BlockProposerPubInput<E: JubjubEngine> {
    pub r: Option<E::Fr>,
    pub priority: Option<E::Fr>,
    pub seed_comp: Option<E::Fr>
}

pub struct BlockProposerAuxInput;