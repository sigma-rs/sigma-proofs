use num_bigint::BigUint;
use rand::RngCore;



use sigma_rs::toolbox::sigma::sage_test::TestDRNG;

#[allow(non_snake_case)]
#[test]
fn DRNG_testing() {
    let mut rng = TestDRNG::new(b"hello world");
    println!("Next u32 : {}", rng.next_u32());
    println!("randint : {}", rng.randint(0, 1000000000));
    // println!("randint : {}", rng.randint(0, 52435875175126190479447740508185965837690552500527637822603658699938581184513));
    let low = BigUint::parse_bytes(b"0", 10).unwrap();
    let high = BigUint::parse_bytes(b"73EDA753299D7C00000000000000000000000000000000000000000000000000", 16).unwrap();
    let rand = rng.randint_big(&low, &high);
    println!("{}", rand);
}
