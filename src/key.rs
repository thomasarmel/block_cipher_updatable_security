use crate::polynomial_algebra::{polyadd, polymul_fast, polysub};
use crate::utils::{gen_ternary_poly, gen_uniform_poly, generate_polynomial_modulus};
use crate::{BlockCipherUpdatableSecurityError, POLYNOMIAL_Q};
use polynomial_ring::Polynomial;
use sha3::{Digest, Sha3_256};

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

    fn generate_encryption_factor_polynomial(&self, block_count: u64) -> Polynomial<i64> {
        let super_block_count = block_count >> 1; // floor(block_count/2)
        let a = gen_uniform_poly(self.security_level, POLYNOMIAL_Q as i64, Some(super_block_count));
        let mut key = self.key.clone();
        if block_count & 1 == 1 {
            key = polymul_fast(&key, &key, POLYNOMIAL_Q as i64, &self.modulus_polynomial, self.omega); // square the key if odd block count
        }
        polymul_fast(&a, &key, POLYNOMIAL_Q as i64, &self.modulus_polynomial, self.omega)
    }

    pub(crate) fn generate_encryption_polynomial(&self, block_count: u64) -> Polynomial<i64> {
        let e = gen_ternary_poly(self.security_level, Some(self.generate_error_seed(block_count))); // None to test
        polyadd(
            &self.generate_encryption_factor_polynomial(block_count),
            &e,
            POLYNOMIAL_Q as i64,
            &self.modulus_polynomial
        )
    }

    fn generate_error_seed(&self, block_count: u64) -> u64 {
        let mut hasher = Sha3_256::new();
        self.key.coeffs().iter().map(|coef| coef.to_le_bytes()).for_each(|bytes| hasher.update(&bytes));
        block_count.to_le_bytes().iter().for_each(| x| hasher.update(&x.to_le_bytes()));
        let result = hasher.finalize();
        u64::from_le_bytes(result.as_slice()[0..8].try_into().unwrap())
    }

    pub(crate) fn get_modulus_polynomial(&self) -> &Polynomial<i64> {
        &self.modulus_polynomial
    }

    pub(crate) fn decrypt_block_polynomial(&self, encrypted_block: &Polynomial<i64>, block_count: u64) -> Polynomial<i64> {
        let encryption_block = self.generate_encryption_factor_polynomial(block_count);
        let sub = polysub(
            encrypted_block,
            &encryption_block,
            POLYNOMIAL_Q as i64,
            &self.modulus_polynomial
        );
        Polynomial::new(sub.coeffs().iter().map(|coef| if coef.abs() > POLYNOMIAL_Q as i64 / 4 { POLYNOMIAL_Q as i64 / 2 } else { 0 }).collect())
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