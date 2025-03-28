use polynomial_ring::Polynomial;
use crate::{BlockCipherUpdatableSecurityError, Key, POLYNOMIAL_Q};
use crate::encrypted_block::EncryptedBlock;
use crate::polynomial_algebra::polyadd;

pub(crate) struct PlainBlock {
    block_polynomial: Polynomial<i64>,
    block_count: u64
}

impl PlainBlock {
    pub(crate) fn from_bytes(input_bytes: &[u8], block_count: u64) -> Result<Self, BlockCipherUpdatableSecurityError> {
        let input_bytes_count = input_bytes.len();
        if input_bytes_count == 0 || input_bytes_count.count_ones() != 1 {
            return Err(BlockCipherUpdatableSecurityError::InvalidBlockSize);
        }
        let coefs: Vec<i64> = input_bytes.iter().flat_map(|byte|
            (0..8).rev().map(move |i| ((byte >> i) & 1u8) as i64)
        ).collect();
        Ok(Self {
            block_polynomial: Polynomial::new(coefs),
            block_count
        })
    }

    pub(crate) fn from_polynomial(block_polynomial: Polynomial<i64>, block_count: u64) -> Self {
        Self {
            block_polynomial,
            block_count
        }
    }

    pub(crate) fn encrypt(&self, key: &Key) -> EncryptedBlock {
        EncryptedBlock::new(
            polyadd(
                &self.block_polynomial,
                &key.generate_encryption_polynomial(self.block_count),
                POLYNOMIAL_Q as i64,
                key.get_modulus_polynomial()
            ),
            self.block_count
        )
    }
}