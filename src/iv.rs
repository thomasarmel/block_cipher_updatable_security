use crate::POLYNOMIAL_Q;
use crate::polynomial_algebra::poly_pow_mod;
use crate::utils::gen_uniform_poly;
use polynomial_ring::Polynomial;

pub struct Iv {
    polynomial: Polynomial<i64>,
    initial_security: usize,
}

impl Iv {
    pub fn generate(initial_security: usize) -> Self {
        Self {
            polynomial: gen_uniform_poly(initial_security, POLYNOMIAL_Q as i64, None),
            initial_security,
        }
    }

    pub fn from_polynomial(polynomial: Polynomial<i64>, initial_security: usize) -> Self { // TODO remove
        Self {
            polynomial,
            initial_security,
        }
    }

    pub fn initial_security(&self) -> usize {
        self.initial_security
    }

    pub(crate) fn polynomial(&self) -> &Polynomial<i64> {
        &self.polynomial
    }

    pub(crate) fn pow(&self, exponent: usize, modulo: &Polynomial<i64>) -> Polynomial<i64> {
        poly_pow_mod(
            &self.polynomial,
            exponent,
            POLYNOMIAL_Q as i64,
            &modulo,
        )
    }
}
