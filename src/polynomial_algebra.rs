// Inspired from https://github.com/lattice-based-cryptography/ring-lwe/blob/main/src/utils.rs

use ntt::polymul_ntt;
use polynomial_ring::Polynomial;

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

/// Multiply two polynomials using fast NTT algorithm
/// # Arguments:
///	* `x` - polynomial to be multiplied
/// * `y` - polynomial to be multiplied.
/// * `q` - coefficient modulus.
///	* `f` - polynomial modulus.
/// * `omega` - n-th root of unity
/// # Returns:
///	polynomial in Z_q[X]/(f)
pub(crate) fn polymul_fast(
    x: &Polynomial<i64>,
    y: &Polynomial<i64>,
    q: i64,
    f: &Polynomial<i64>,
    omega: i64
) -> Polynomial<i64> {
    let n1 = x.coeffs().len();
    let n2 = y.coeffs().len();
    // Compute the nearest power of 2 at least twice the max of input degrees+1
    let n = 2* std::cmp::max(n1, n2).next_power_of_two();
    // Pad coefficients
    let x_pad = {
        let mut coeffs = x.coeffs().to_vec();
        coeffs.resize(n, 0);
        coeffs
    };
    let y_pad = {
        let mut coeffs = y.coeffs().to_vec();
        coeffs.resize(n, 0);
        coeffs
    };

    // Perform the polynomial multiplication
    let r_coeffs = polymul_ntt(&x_pad, &y_pad, n, q, omega);

    // Construct the result polynomial and reduce modulo f
    let mut r = Polynomial::new(r_coeffs);
    r = polyrem(r,f);
    mod_coeffs(r, q)
}

/// Polynomial remainder of x modulo f assuming f=x^n+1
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `f` - polynomial modulus
/// # Returns:
/// polynomial in Z[X]/(f)
pub(crate) fn polyrem(x: Polynomial<i64>, f: &Polynomial<i64>) -> Polynomial<i64> {
    let n = f.coeffs().len()-1;
    let mut coeffs = x.coeffs().to_vec();
    if coeffs.len() < n+1 {
        Polynomial::new(coeffs)
    } else {
        for i in n..coeffs.len() {
            coeffs[i % n] = coeffs[i % n]+(-1 as i64).pow((i/n).try_into().unwrap())*coeffs[i];
        }
        coeffs.resize(n,0);
        Polynomial::new(coeffs)
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
pub(crate) fn polyadd(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
    let mut r = x+y;
    r = polyrem(r,f);
    if modulus != 0 {
        mod_coeffs(r, modulus)
    }
    else {
        r
    }
}