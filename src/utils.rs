// Inspired from https://github.com/lattice-based-cryptography/ring-lwe/blob/main/src/utils.rs

use crate::polynomial_algebra::mod_coeffs;
use polynomial_ring::Polynomial;
use rand::SeedableRng;
use rand::distr::{Distribution, Uniform};
use rand::rngs::StdRng;

fn get_rng_from_seed(seed: Option<u64>) -> StdRng {
    match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_os_rng(),
    }
}

/// Generate a uniform polynomial
/// # Arguments:
///	* `size` - number of coefficients
/// * `q` - coefficient modulus
/// * `seed` - random seed
/// # Returns:
///	uniform polynomial with coefficients in {0,1,...,q-1}
pub(crate) fn gen_uniform_poly(size: usize, q: i64, seed: Option<u64>) -> Polynomial<i64> {
    let between = Uniform::new(0, q).unwrap();
    let mut rng = get_rng_from_seed(seed);
    let mut coeffs = vec![0i64; size];
    for i in 0..size {
        coeffs[i] = between.sample(&mut rng);
    }
    mod_coeffs(Polynomial::new(coeffs), q)
}

/// Generate a ternary polynomial
/// # Arguments:
///	* `size` - number of coefficients
/// * `seed` - random seed
/// # Returns:
///	ternary polynomial with coefficients in {-1,0,+1}
pub(crate) fn gen_ternary_poly(size: usize, seed: Option<u64>) -> Polynomial<i64> {
    let between = Uniform::new(-1, 2).unwrap();
    let mut rng = get_rng_from_seed(seed);
    let mut coeffs = vec![0i64; size];
    for i in 0..size {
        coeffs[i] = between.sample(&mut rng);
    }
    Polynomial::new(coeffs)
}

/*
/// Generate polynomial modulus (x^n + 1 representation)
pub(crate) fn generate_polynomial_modulus(polynomial_size: usize) -> Polynomial<i64> {
    let mut coeffs = vec![0i64; polynomial_size + 1];
    coeffs[0] = 1;
    coeffs[polynomial_size] = 1;
    Polynomial::new(coeffs)
}*/

/// Generate polynomial for super-block merging (x^n representation)
pub(crate) fn generate_merging_block_polynomial(polynomial_size: usize) -> Polynomial<i64> {
    let mut coeffs = vec![0i64; polynomial_size + 1];
    coeffs[polynomial_size] = 1;
    Polynomial::new(coeffs)
}

/// nearest integer to the ratio a/b
/// # Arguments:
///	* `a` - numerator
/// * `b` - denominator
/// # Returns:
///	nearest integer to the ratio a/b
#[allow(dead_code)]
pub(crate) fn nearest_int(a: i64, b: i64) -> i64 {
    if a > 0 {
        (a + b / 2) / b
    } else {
        -((-a + b / 2) / b)
    }
}
