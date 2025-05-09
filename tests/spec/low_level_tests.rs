use rand::RngCore;
use group::{Group, ff::Field};
use bls12_381::{G1Projective, G1Affine};
use num_bigint::BigUint;

use crate::test_drng::TestDRNG;

type Gp = G1Projective;
type Ga = G1Affine;

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


#[allow(non_snake_case)]
#[test]
fn Scalar_test() {
    let rng = TestDRNG::new(b"hello world");
    let y = <Gp as Group>::Scalar::random(rng);
    let ZERO = <Gp as Group>::Scalar::ZERO;
    let ONE = y * y.invert().unwrap();
    let ONE_inv = ONE.invert().unwrap();
    let TWO = ONE + ONE;
    let TWO_INV = TWO.invert().unwrap();
    println!("y = {}", y);
    println!("ZERO = {}", ZERO);
    println!("ONE = {}", ONE);
    println!("ONE_inv = {}", ONE_inv);
    println!("TWO = {}", TWO);
    println!("TWO_INV = {}", TWO_INV);
}

#[allow(non_snake_case)]
#[test]
fn DRNG_test_on_Scalar() {
    let mut rng = TestDRNG::new(b"hello world");
    let x = G1Projective::random(&mut rng);
    let y = G1Projective::random(&mut rng);
    println!("x = {}", x);
    println!("y = {}", y);
}


#[allow(non_snake_case)]
#[test]
fn DRNG_test_on_Group() {
    let mut _rng = TestDRNG::new(b"hello world");
    let H = Ga::identity();
    let _bytes = H.to_uncompressed();
    println!("H : {}", H);
}