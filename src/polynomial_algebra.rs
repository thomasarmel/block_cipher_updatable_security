// Inspired from https://github.com/lattice-based-cryptography/ring-lwe/blob/main/src/utils.rs

use crate::{POLYMULTIPLIER, POLYNOMIAL_Q};
use ntt::polymul_ntt;
use polynomial_ring::Polynomial;
use rand_distr::num_traits::{One};
use std::collections::HashMap;
use std::sync::Mutex;

/// Take remainder of the coefficients of a polynom by a given modulus
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `modulus` - coefficient modulus
/// # Returns:
/// polynomial in Z_modulus[X]
pub(crate) fn mod_coeffs(x: Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
    let coeffs = x.coeffs();
    let mut newcoeffs = Vec::with_capacity(coeffs.len());
    let mut c;
    if coeffs.len() == 0 {
        // return original input for the zero polynomial
        x
    } else {
        for i in 0..coeffs.len() {
            c = coeffs[i].rem_euclid(modulus);
            if c > modulus / 2 {
                c = c - modulus;
            }
            newcoeffs.push(c);
        }
        Polynomial::new(newcoeffs)
    }
}

pub(crate) struct PolyMultiplier {
    omega_cache: Mutex<HashMap<usize, i64>>
}

impl PolyMultiplier {
    pub(crate) fn new() -> Self {
        Self {
            omega_cache: Mutex::new(HashMap::new())
        }
    }

    /// Multiply two polynomials using fast NTT algorithm
    /// # Arguments:
    ///	* `x` - polynomial to be multiplied
    /// * `y` - polynomial to be multiplied.
    /// * `q` - coefficient modulus.
    ///	* `modulus` - polynomial modulus.
    /// # Returns:
    ///	polynomial in Z_q[X]/(f)
    pub(crate) fn polymul_fast(
        &self,
        x: &Polynomial<i64>,
        y: &Polynomial<i64>,
        modulus: &Polynomial<i64>,
    ) -> Polynomial<i64> {
        let q = POLYNOMIAL_Q as i64;
        // NTT requires n to be a power of two
        // product will have degree of deg(a) + deg(b) + 1
        // we want n to be the smallest power of 2 that's >= deg(a) + deg(b) + 1

        /*let omega = ntt::omega(q, (x.deg().unwrap() + y.deg().unwrap() + 1).next_power_of_two()); // TODO
        self.omega_cache.lock().unwrap().insert(1, 3);*/
        let mut omega_cache = self.omega_cache.lock().unwrap();
        let omega_index = (x.deg().unwrap() + y.deg().unwrap() + 1).next_power_of_two();
        let omega = omega_cache.entry(omega_index).or_insert_with(|| {
            ntt::omega(q, omega_index)
        });

        let n1 = x.coeffs().len();
        let n2 = y.coeffs().len();
        // Compute the nearest power of 2 at least twice the max of input degrees+1
        let n = 2 * std::cmp::max(n1, n2).next_power_of_two();
        // Pad coefficients
        let x_pad = {
            let mut coeffs = vec![0; n];
            coeffs[..n1].copy_from_slice(x.coeffs());
            coeffs
        };
        let y_pad = {
            let mut coeffs = vec![0; n];
            coeffs[..n2].copy_from_slice(y.coeffs());
            coeffs
        };

        // Perform the polynomial multiplication
        let r_coeffs = polymul_ntt(&x_pad, &y_pad, n, q, *omega);

        // Construct the result polynomial and reduce modulo f
        let mut r = Polynomial::new(r_coeffs);
        r = polyrem(r, modulus, q);
        mod_coeffs(r, q)
    }
}

/// Multiply two polynomials
/// # Arguments:
///	* `x` - polynomial to be multiplied
/// * `y` - polynomial to be multiplied.
/// * `modulus` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_q[X]/(f)
#[allow(dead_code)]
pub fn polymul(x : &Polynomial<i64>, y : &Polynomial<i64>, q : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
    let mut r = x*y;
    r = polyrem(r,f, q);
    if q != 0 {
        mod_coeffs(r, q)
    }
    else{
        r
    }
}

#[allow(dead_code)]
pub(crate) fn poly_pow_mod(
    x: &Polynomial<i64>,
    n: usize,
    modulus: &Polynomial<i64>,
) -> Polynomial<i64> {
    let mut r = Polynomial::one();
    let mut x = x.clone();
    let mut n = n;
    while n > 0 {
        if n % 2 == 1 {
            r = POLYMULTIPLIER.polymul_fast(&r, &x, modulus);
        }
        x = POLYMULTIPLIER.polymul_fast(&x, &x, modulus);
        n /= 2;
    }
    r
}

/// Computes a / b mod q, returning the result in [-q/2, q/2]
fn moddiv_centered(a: i64, b: i64, q: i64) -> i64 {
    if b % q == 0 {
        panic!("Division by zero modulo {}", q);
    }

    let inv_b = modinv(b, q);
    let result = (a * inv_b).rem_euclid(q);
    centered_mod(result, q)
}

/// Modular inverse of b mod q using Fermat’s Little Theorem (q prime)
fn modinv(b: i64, q: i64) -> i64 {
    modpow(b.rem_euclid(q), q - 2, q)
}

/// Modular exponentiation: base^exp mod q
fn modpow(mut base: i64, mut exp: i64, q: i64) -> i64 {
    base = base.rem_euclid(q);
    let mut result = 1;
    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base % q;
        }
        base = base * base % q;
        exp /= 2;
    }
    result
}

fn centered_mod(a: i64, q: i64) -> i64 {
    let r = a.rem_euclid(q);
    if r > q / 2 {
        r - q
    } else {
        r
    }
}

/// Polynomial remainder of x modulo f
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `f` - polynomial modulus
/// # Returns:
/// polynomial in Z[X]/(f)
pub(crate) fn polyrem(x: Polynomial<i64>, f: &Polynomial<i64>, q: i64) -> Polynomial<i64> {
    let f_coeffs = f.coeffs();
    let f_deg = f.deg().unwrap();
    let x_deg = x.deg().unwrap();

    let mut r = x;

    for i in (f_deg..=x_deg).rev() {
        let t = moddiv_centered(r.coeffs()[i], f_coeffs[f_deg], q);
        let mut coefs_r = r.coeffs().to_vec();
        coefs_r[i] = 0;
        for j in 0..f_deg {
            coefs_r[i - f_deg + j] = centered_mod(coefs_r[i - f_deg + j] - f_coeffs[j] * t, q);
        }
        r = Polynomial::new(coefs_r);
    }

    r
}

/// Additive inverse of a polynomial
/// # Arguments:
///	* `x` - polynomial to be inverted
/// * `modulus` - coefficient modulus.
/// # Returns:
///	polynomial in Z_modulus[X]
fn polyinv(x: &Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
    //Additive inverse of polynomial x modulo modulus
    let y = -x;
    if modulus != 0 {
        mod_coeffs(y, modulus)
    } else {
        y
    }
}

/// Add two polynomials
/// # Arguments:
///	* `x` - polynomial to be added
/// * `y` - polynomial to be added.
/// * `modulus` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_modulus[X]/(f)
pub(crate) fn polyadd(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    modulus: i64,
    f: &Polynomial<i64>,
) -> Polynomial<i64> {
    let mut r = x + y;
    r = polyrem(r, f, modulus);
    if modulus != 0 {
        mod_coeffs(r, modulus)
    } else {
        r
    }
}

/// Subtract two polynomials
/// # Arguments:
///	* `x` - polynomial to be subtracted
/// * `y` - polynomial to be subtracted.
/// * `modulus` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_modulus[X]/(f)
pub(crate) fn polysub(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    modulus: i64,
    f: &Polynomial<i64>,
) -> Polynomial<i64> {
    polyadd(x, &polyinv(y, modulus), modulus, f)
}

#[cfg(test)]
mod tests {
    use std::ops::Rem;
    use crate::POLYMULTIPLIER;
    use polynomial_ring::Polynomial;

    #[test]
    fn test_poly_pow_mod() {
        let x = Polynomial::new(vec![1, 2, 3]);
        let modulo = Polynomial::new(vec![1, 0, 0, 1]);
        let result = super::poly_pow_mod(&x, 2, &modulo);
        let expected = POLYMULTIPLIER.polymul_fast(&x, &x, &modulo);
        assert_eq!(result, expected);

        let expected = POLYMULTIPLIER.polymul_fast(&expected, &x, &modulo);
        let result = super::poly_pow_mod(&x, 3, &modulo);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_polyrem() {
        let x = Polynomial::new(vec![0, 0, 9]);
        let f = Polynomial::new(vec![10, 4, 1]);
        let result = super::polyrem(x.clone(), &f, 13);
        assert_eq!(result, super::mod_coeffs(x.rem(f), 13));
    }
}
