// Inspired from https://github.com/lattice-based-cryptography/ring-lwe/blob/main/src/utils.rs

use ntt::polymul_ntt;
use polynomial_ring::Polynomial;
use rand_distr::num_traits::One;

/// Take remainder of the coefficients of a polynom by a given modulus
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `modulus` - coefficient modulus
/// # Returns:
/// polynomial in Z_modulus[X]
pub(crate) fn mod_coeffs(x: Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
    let coeffs = x.coeffs();
    let mut newcoeffs = vec![];
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

/// Multiply two polynomials using fast NTT algorithm
/// # Arguments:
///	* `x` - polynomial to be multiplied
/// * `y` - polynomial to be multiplied.
/// * `q` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_q[X]/(f)
pub(crate) fn polymul_fast(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    q: i64,
    f: &Polynomial<i64>,
) -> Polynomial<i64> {
    // NTT requires n to be a power of two
    // product will have degree of deg(a) + deg(b) + 1
    // we want n to be the smallest power of 2 that's >= deg(a) + deg(b) + 1
    let omega = ntt::omega(q, (x.deg().unwrap() + y.deg().unwrap() + 1).next_power_of_two());
    
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
    let r_coeffs = polymul_ntt(&x_pad, &y_pad, n, q, omega);

    // Construct the result polynomial and reduce modulo f
    let mut r = Polynomial::new(r_coeffs);
    r = polyrem(r, f);
    mod_coeffs(r, q)
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
    r = polyrem(r,f);
    if q != 0 {
        mod_coeffs(r, q)
    }
    else{
        r
    }
}

pub(crate) fn poly_pow_mod(
    x: &Polynomial<i64>,
    n: usize,
    q: i64,
    modulus: &Polynomial<i64>,
) -> Polynomial<i64> {
    let mut r = Polynomial::one();
    let mut x = x.clone();
    let mut n = n;
    while n > 0 {
        if n % 2 == 1 {
            r = polymul_fast(&r, &x, q, modulus);
        }
        x = polymul_fast(&x, &x, q, modulus);
        n /= 2;
    }
    r
}

/// Polynomial remainder of x modulo f assuming f=x^n+1
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `f` - polynomial modulus
/// # Returns:
/// polynomial in Z[X]/(f)
pub(crate) fn polyrem(x: Polynomial<i64>, f: &Polynomial<i64>) -> Polynomial<i64> {
    let n = f.coeffs().len() - 1;
    let mut coeffs = x.coeffs().to_vec();
    if coeffs.len() < n + 1 {
        Polynomial::new(coeffs)
    } else {
        for i in n..coeffs.len() {
            coeffs[i % n] =
                coeffs[i % n] + (-1 as i64).pow((i / n).try_into().unwrap()) * coeffs[i];
        }
        coeffs.resize(n, 0);
        Polynomial::new(coeffs)
    }
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
    r = polyrem(r, f);
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
    use crate::polynomial_algebra::{polymul_fast, polymul};
    use polynomial_ring::Polynomial;
    use crate::POLYNOMIAL_Q;

    #[test]
    fn test_poly_pow_mod() {
        let x = Polynomial::new(vec![1, 2, 3]);
        let modulo = Polynomial::new(vec![1, 0, 0, 1]);
        let result = super::poly_pow_mod(&x, 2, 7, &modulo);
        let expected = polymul_fast(&x, &x, 7, &modulo);
        assert_eq!(result, expected);

        let expected = polymul_fast(&expected, &x, 7, &modulo);
        let result = super::poly_pow_mod(&x, 3, 7, &modulo);
        assert_eq!(result, expected);
    }
}
