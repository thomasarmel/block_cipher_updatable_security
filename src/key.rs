use polynomial_ring::Polynomial;
use crate::{BlockCipherUpdatableSecurityError, POLYNOMIAL_Q};
use crate::polynomial_algebra::{polyadd, polymul_fast};
use crate::utils::{gen_ternary_poly, gen_uniform_poly, generate_polynomial_modulus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    key: Polynomial<i64>,
    security_level: usize,
    modulus_polynomial: Polynomial<i64>, // no need for serialization
    omega: i64, // no need for serialization
}

impl Key {
    pub fn generate(key_size_bits_security_level: usize) -> Result<Self, BlockCipherUpdatableSecurityError> {
        if key_size_bits_security_level.count_ones() != 1 || key_size_bits_security_level < 128 {
            return Err(BlockCipherUpdatableSecurityError::InvalidKeySize);
        }
        Ok(Self {
            key: gen_uniform_poly(key_size_bits_security_level, POLYNOMIAL_Q as i64, None),
            security_level: key_size_bits_security_level,
            modulus_polynomial: generate_polynomial_modulus(key_size_bits_security_level),
            omega: ntt::omega(POLYNOMIAL_Q as i64, 2*key_size_bits_security_level)
        })
    }

    pub fn security_level(&self) -> usize {
        self.security_level
    }

    pub(crate) fn generate_encryption_polynomial(&self, block_count: u64) -> Polynomial<i64> {
        let super_block_count = block_count >> 1; // floor(block_count/2)
        let a = gen_uniform_poly(self.security_level, POLYNOMIAL_Q as i64, Some(super_block_count));
        let e = gen_ternary_poly(self.security_level, None); // Todo: use hash of block count and key as seed ?
        polyadd(
            &polymul_fast(&a, &self.key, POLYNOMIAL_Q as i64, &self.modulus_polynomial, self.omega),
            &e,
            POLYNOMIAL_Q as i64,
            &self.modulus_polynomial
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let key = Key::generate(128).unwrap();
        assert_eq!(key.security_level(), 128);

        let key = Key::generate(256).unwrap();
        assert_eq!(key.security_level(), 256);

        let key = Key::generate(64);
        assert!(key.is_err());
        assert_eq!(key.unwrap_err(), BlockCipherUpdatableSecurityError::InvalidKeySize);

        let key = Key::generate(130);
        assert!(key.is_err());
        assert_eq!(key.unwrap_err(), BlockCipherUpdatableSecurityError::InvalidKeySize);
    }
}