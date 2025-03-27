use polynomial_ring::Polynomial;
use crate::{BlockCipherUpdatableSecurityError, POLYNOMIAL_Q};
use crate::utils::gen_uniform_poly;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    key: Polynomial<i64>,
    security_level: usize,
}

impl Key {
    pub fn generate(key_size_bits_security_level: usize) -> Result<Self, BlockCipherUpdatableSecurityError> {
        if key_size_bits_security_level.count_ones() != 1 || key_size_bits_security_level < 128 {
            return Err(BlockCipherUpdatableSecurityError::InvalidKeySize);
        }
        Ok(Self {
            key: gen_uniform_poly(key_size_bits_security_level, POLYNOMIAL_Q as i64, None),
            security_level: key_size_bits_security_level,
        })
    }

    pub fn security_level(&self) -> usize {
        self.security_level
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