
// Inspired from https://github.com/lattice-based-cryptography/ring-lwe/blob/main/src/utils.rs

use polynomial_ring::Polynomial;
use rand::distr::{Distribution, Uniform};
use rand::rngs::StdRng;
use rand::SeedableRng;


/// Take remainder of the coefficients of a polynom by a given modulus
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `modulus` - coefficient modulus
/// # Returns:
/// polynomial in Z_modulus[X]
pub(crate) fn mod_coeffs(x : Polynomial<i64>, modulus : i64) -> Polynomial<i64> {

    let coeffs = x.coeffs();
    let mut newcoeffs = vec![];
    let mut c;
    if coeffs.len() == 0 {
        // return original input for the zero polynomial
        x
    } else {
        for i in 0..coeffs.len() {
            c = coeffs[i].rem_euclid(modulus);
            if c > modulus/2 {
                c = c-modulus;
            }
            newcoeffs.push(c);
        }
        Polynomial::new(newcoeffs)
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
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_os_rng(),
    };
    let mut coeffs = vec![0i64; size];
    for i in 0..size {
        coeffs[i] = between.sample(&mut rng);
    }
    mod_coeffs(Polynomial::new(coeffs),q)
}