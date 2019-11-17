//extern {
//    pub fn hello_world();
//    pub fn init();
//    pub fn check_value(u: *mut u8);
//}
//
//#[test]
//pub fn experiment() {
//    use rand::thread_rng;
//    use pairing::bls12_381::Bls12;
//    use ff::{Field, PrimeField, ScalarEngine};
//
//    let rng = &mut thread_rng();
//    let mut num = <Bls12 as ScalarEngine>::Fr::random(rng);
//    let ptr: *mut <Bls12 as ScalarEngine>::Fr = &mut num;
//
//    unsafe {
//        hello_world();
//        init();
//    }
//    println!("{}", num.into_repr());
//    unsafe {
//        check_value(ptr as *mut u8);
//    }
//}