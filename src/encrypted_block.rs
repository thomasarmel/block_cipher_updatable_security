use polynomial_ring::Polynomial;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EncryptedBlock {
    polynomial: Polynomial<i64>,
    block_count: u64,
}

impl EncryptedBlock {
    pub(crate) fn new(polynomial: Polynomial<i64>, block_count: u64) -> Self {
        Self {
            polynomial,
            block_count,
        }
    }

    pub(crate) fn polynomial(&self) -> &Polynomial<i64> {
        &self.polynomial
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.polynomial.coeffs().iter().map(|&coeff| coeff.to_le_bytes().to_vec()).flatten().collect()
    }

    // inverse of to_bytes
    pub(crate) fn from_bytes(encrypted_bytes: &[u8], block_count: u64) -> Self {
        let coefs: Vec<i64> = encrypted_bytes.chunks(8).map(|chunk| {
            let mut byte = [0u8; 8];
            byte.copy_from_slice(chunk);
            i64::from_le_bytes(byte)
        }).collect();
        Self {
            polynomial: Polynomial::new(coefs),
            block_count,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_encrypted_block_to_bytes() {
        let encrypted_block = super::EncryptedBlock::new(polynomial_ring::Polynomial::new(vec![1, 2, -3003, 602]), 1);
        let bytes = encrypted_block.to_bytes();
        let decrypted_block = super::EncryptedBlock::from_bytes(&bytes, 1);
        assert_eq!(encrypted_block, decrypted_block);
    }
}