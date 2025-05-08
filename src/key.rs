use crate::irreducible_modulos::IrreducibleModulo;
use crate::polynomial_algebra::{polyadd, polysub};
use crate::utils::{gen_ternary_poly, gen_uniform_poly};
use crate::{BlockCipherUpdatableSecurityError, Iv, POLYMULTIPLIER, POLYNOMIAL_Q};
use polynomial_ring::Polynomial;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    key: Polynomial<i64>,
    security_level: usize,
    key_generation: usize, // Generation 0: first key for cipher etc.
    modulus_polynomial: Polynomial<i64>, // no need for serialization
}

impl Key {
    pub fn generate(key_size_bits_security_level: usize, key_generation: usize) -> Result<Self, BlockCipherUpdatableSecurityError> {
        if key_size_bits_security_level.count_ones() != 1 || key_size_bits_security_level < 128 {
            return Err(BlockCipherUpdatableSecurityError::InvalidKeySize);
        }
        Ok(Self {
            key: gen_uniform_poly(key_size_bits_security_level, POLYNOMIAL_Q as i64, None),
            security_level: key_size_bits_security_level,
            key_generation,
            modulus_polynomial: IrreducibleModulo::get_irreducible_modulo(
                key_size_bits_security_level,
            ),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn from_polynomial(key: &Polynomial<i64>, security_level: usize, key_generation: usize) -> Self {
        Self {
            key: key.clone(),
            security_level,
            key_generation,
            modulus_polynomial: IrreducibleModulo::get_irreducible_modulo(security_level),
        }
    }

    pub fn security_level(&self) -> usize {
        self.security_level
    }

    pub fn key_generation(&self) -> usize {
        self.key_generation
    }

    pub(crate) fn generate_encryption_factor_polynomial(
        &self,
        iv: &Iv,
        block_count: u64,
    ) -> Polynomial<i64> {
        let a = iv.pow(((block_count as usize) << self.key_generation) + 1, &self.modulus_polynomial);
        POLYMULTIPLIER.polymul_fast(
            &a,
            &self.key,
            &self.modulus_polynomial,
        )
    }

    pub(crate) fn generate_encryption_polynomial(
        &self,
        iv: &Iv,
        block_count: u64,
    ) -> Polynomial<i64> {
        let e = gen_ternary_poly(
            self.security_level,
            Some(self.generate_error_seed(block_count)),
        ); // None to test
        polyadd(
            &self.generate_encryption_factor_polynomial(iv, block_count),
            &e,
            POLYNOMIAL_Q as i64,
            &self.modulus_polynomial,
        )
    }

    fn generate_error_seed(&self, block_count: u64) -> u64 {
        let mut hasher = Sha3_256::new();
        self.key
            .coeffs()
            .iter()
            .map(|coef| coef.to_le_bytes())
            .for_each(|bytes| hasher.update(&bytes));
        block_count
            .to_le_bytes()
            .iter()
            .for_each(|x| hasher.update(&x.to_le_bytes()));
        let result = hasher.finalize();
        u64::from_le_bytes(result.as_slice()[0..8].try_into().unwrap())
    }

    pub(crate) fn get_modulus_polynomial(&self) -> &Polynomial<i64> {
        &self.modulus_polynomial
    }

    pub(crate) fn polynomial(&self) -> &Polynomial<i64> {
        &self.key
    }

    pub(crate) fn decrypt_block_polynomial(
        &self,
        encrypted_block: &Polynomial<i64>,
        iv: &Iv,
        block_count: u64,
    ) -> Polynomial<i64> {
        let encryption_block = self.generate_encryption_factor_polynomial(iv, block_count);
        let sub = polysub(
            encrypted_block,
            &encryption_block,
            POLYNOMIAL_Q as i64,
            &self.modulus_polynomial,
        );
        Polynomial::new(
            sub.coeffs()
                .iter()
                .map(|coef| {
                    if coef.abs() > POLYNOMIAL_Q as i64 / 4 {
                        POLYNOMIAL_Q as i64 / 2
                    } else {
                        0
                    }
                })
                .collect(),
        )
    }

    pub(crate) fn prepare_next_multiplier(&self, iv: &Iv, block_count: usize) -> Polynomial<i64> {
        let this_modulo = IrreducibleModulo::get_irreducible_modulo(self.security_level());
        let next_modulo = IrreducibleModulo::get_irreducible_modulo(self.security_level() * 2);
        let mul_next_modulo = POLYMULTIPLIER.polymul_fast(
            &self.polynomial(),
            &iv.pow((block_count << self.key_generation) + 1, &next_modulo),
            &next_modulo,
        );
        let mul_this_modulo = POLYMULTIPLIER.polymul_fast(
            &self.polynomial(),
            &iv.pow((block_count << self.key_generation) + 1, &this_modulo),
            &this_modulo,
        );
        let error = gen_ternary_poly(self.security_level << 1, None);
        polyadd(
            &error,
            &polysub(
                &mul_next_modulo,
                &mul_this_modulo,
                POLYNOMIAL_Q as i64,
                &next_modulo,
            ),
            POLYNOMIAL_Q as i64,
            &next_modulo
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let key = Key::generate(128, 0).unwrap();
        assert_eq!(key.security_level(), 128);

        let key = Key::generate(256, 0).unwrap();
        assert_eq!(key.security_level(), 256);

        let key = Key::generate(64, 0);
        assert!(key.is_err());
        assert_eq!(
            key.unwrap_err(),
            BlockCipherUpdatableSecurityError::InvalidKeySize
        );

        let key = Key::generate(130, 0);
        assert!(key.is_err());
        assert_eq!(
            key.unwrap_err(),
            BlockCipherUpdatableSecurityError::InvalidKeySize
        );
    }
}
