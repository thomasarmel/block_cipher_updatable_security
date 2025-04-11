use std::cell::RefCell;
use std::collections::HashMap;
use crate::POLYNOMIAL_Q;
use crate::polynomial_algebra::{poly_pow_mod, polymul_fast};
use crate::utils::gen_uniform_poly;
use polynomial_ring::Polynomial;

pub struct Iv {
    polynomial: Polynomial<i64>,
    initial_security: usize,
    pow_cache: RefCell<HashMap<usize, Vec<Polynomial<i64>>>>,
}

impl Iv {
    pub fn generate(initial_security: usize) -> Self {
        let polynomial = gen_uniform_poly(initial_security, POLYNOMIAL_Q as i64, None);
        let mut cache = HashMap::new();
        cache.insert(initial_security, vec![polynomial.clone()]);
        Self {
            polynomial: polynomial.clone(),
            initial_security,
            pow_cache: RefCell::new(cache),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_polynomial(polynomial: Polynomial<i64>, initial_security: usize) -> Self {
        let mut cache = HashMap::new();
        cache.insert(initial_security, vec![polynomial.clone()]);
        Self {
            polynomial: polynomial.clone(),
            initial_security,
            pow_cache: RefCell::new(cache),
        }
    }

    pub fn initial_security(&self) -> usize {
        self.initial_security
    }

    pub(crate) fn polynomial(&self) -> &Polynomial<i64> {
        &self.polynomial
    }

    pub(crate) fn pow(&self, exponent: usize, modulo: &Polynomial<i64>) -> Polynomial<i64> { // TODO cache only works for first encryption
        const ACTIVATE_CACHE: bool = false;
        if ACTIVATE_CACHE {
            let index = exponent - 1;
            let cache_position = modulo.deg().unwrap();
            if !self.pow_cache.borrow().contains_key(&cache_position) {
                self.pow_cache.borrow_mut().insert(cache_position, vec![self.polynomial.clone()]);
            }
            let cache_len = self.pow_cache.borrow().get(&cache_position).unwrap().len();
            if cache_len == index {
                let next = polymul_fast(&self.polynomial, &self.pow_cache.borrow().get(&cache_position).unwrap()[index - 1], POLYNOMIAL_Q as i64, modulo);
                self.pow_cache.borrow_mut().get_mut(&cache_position).unwrap().push(next.clone());
                return next;
            }
            if cache_len > index {
                return self.pow_cache.borrow().get(&cache_position).unwrap()[index].clone();
            }
        }
        poly_pow_mod(
            &self.polynomial,
            exponent,
            POLYNOMIAL_Q as i64,
            &modulo,
        )
    }
}
