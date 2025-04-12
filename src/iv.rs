use crate::utils::gen_uniform_poly;
use crate::{POLYMULTIPLIER, POLYNOMIAL_Q};
use polynomial_ring::Polynomial;
use std::cell::RefCell;
use std::collections::HashMap;

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

    #[allow(dead_code)]
    pub(crate) fn polynomial(&self) -> &Polynomial<i64> {
        &self.polynomial
    }

    pub(crate) fn pow(&self, exponent: usize, modulo: &Polynomial<i64>) -> Polynomial<i64> {
        let index = exponent - 1;
        let cache_position = modulo.deg().unwrap();
        let mut table_cache_vec = self.pow_cache.borrow_mut();
        if !table_cache_vec.contains_key(&cache_position) {
            table_cache_vec.insert(cache_position, vec![self.polynomial.clone()]);
        }
        let cache_vec = table_cache_vec.get_mut(&cache_position).unwrap();
        while cache_vec.len() <= index {
            let next = POLYMULTIPLIER.polymul_fast(
                &self.polynomial,
                &cache_vec[cache_vec.len() - 1],
                modulo,
            );
            cache_vec.push(next.clone());
        }
        cache_vec[index].clone()
    }
}
