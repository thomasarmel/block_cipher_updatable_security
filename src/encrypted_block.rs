use crate::plain_block::PlainBlock;
use crate::{Iv, Key};
use polynomial_ring::Polynomial;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EncryptedBlock {
    enc_polynomial: Polynomial<i64>,
    mul_polynomial: Polynomial<i64>,
    block_count: u64,
}

impl EncryptedBlock {
    pub(crate) fn new(
        enc_polynomial: Polynomial<i64>,
        mul_polynomial: Polynomial<i64>,
        block_count: u64,
    ) -> Self {
        Self {
            enc_polynomial,
            mul_polynomial,
            block_count,
        }
    }

    pub(crate) fn enc_polynomial(&self) -> &Polynomial<i64> {
        &self.enc_polynomial
    }

    pub(crate) fn mul_polynomial(&self) -> &Polynomial<i64> {
        &self.mul_polynomial
    }

    #[allow(dead_code)]
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap()
    }

    // inverse of to_bytes
    #[allow(dead_code)]
    pub(crate) fn from_bytes(encrypted_bytes: &[u8]) -> Self {
        serde_cbor::from_slice(encrypted_bytes).unwrap()
    }

    pub(crate) fn block_count(&self) -> u64 {
        self.block_count
    }

    pub(crate) fn decrypt(&self, key: &Key, iv: &Iv) -> PlainBlock {
        PlainBlock::from_polynomial(
            key.decrypt_block_polynomial(&self.enc_polynomial, iv, self.block_count),
            self.block_count,
            key.security_level(),
        )
    }
}

#[cfg(test)]
mod tests {
    use rand_distr::num_traits::Zero;

    #[test]
    fn test_encrypted_block_to_bytes() {
        let encrypted_block = super::EncryptedBlock::new(
            polynomial_ring::Polynomial::new(vec![1, 2, -3003, 602]),
            polynomial_ring::Polynomial::zero(),
            1,
        );
        let bytes = encrypted_block.to_bytes();
        let decrypted_block = super::EncryptedBlock::from_bytes(&bytes);
        assert_eq!(encrypted_block, decrypted_block);
    }
}
