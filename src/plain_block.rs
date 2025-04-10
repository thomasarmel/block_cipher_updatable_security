use crate::encrypted_block::EncryptedBlock;
use crate::irreducible_modulos::IrreducibleModulo;
use crate::polynomial_algebra::{polyadd, polymul_fast, polysub};
use crate::{BlockCipherUpdatableSecurityError, Iv, Key, POLYNOMIAL_Q};
use polynomial_ring::Polynomial;

pub(crate) struct PlainBlock {
    block_polynomial: Polynomial<i64>,
    block_count: u64,
    block_size_bits: usize,
}

impl PlainBlock {
    pub(crate) fn from_bytes(
        input_bytes: &[u8],
        block_count: u64,
    ) -> Result<Self, BlockCipherUpdatableSecurityError> {
        let input_bytes_count = input_bytes.len();
        if input_bytes_count == 0 || input_bytes_count.count_ones() != 1 {
            return Err(BlockCipherUpdatableSecurityError::InvalidBlockSize);
        }
        let coefs: Vec<i64> = input_bytes
            .iter()
            .flat_map(|byte| {
                (0..8)
                    .rev()
                    .map(move |i| ((byte >> i) & 1u8) as i64 * (POLYNOMIAL_Q as i64 / 2))
            })
            .collect();
        Ok(Self {
            block_polynomial: Polynomial::new(coefs),
            block_count,
            block_size_bits: input_bytes_count * 8,
        })
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.block_polynomial.coeffs().iter().enumerate().fold(
            vec![0u8; self.block_size_bits / 8],
            |mut acc, (i, &coef)| {
                let coef = if coef == 0 { 0 } else { 1 };
                acc[i / 8] |= (coef << (7 - (i % 8))) as u8;
                acc
            },
        )
    }

    pub(crate) fn from_polynomial(
        block_polynomial: Polynomial<i64>,
        block_count: u64,
        block_size_bits: usize,
    ) -> Self {
        Self {
            block_polynomial,
            block_count,
            block_size_bits,
        }
    }

    pub(crate) fn encrypt(&self, key: &Key, iv: &Iv) -> EncryptedBlock {
        let this_modulo = IrreducibleModulo::get_irreducible_modulo(key.security_level());
        let next_modulo = IrreducibleModulo::get_irreducible_modulo(key.security_level() * 2);
        let mul_next_modulo = polymul_fast(
            &key.polynomial(),
            &iv.pow(self.block_count as usize + 1, &next_modulo), // TODO: pow((block_count * multiplicator) + 1)
            POLYNOMIAL_Q as i64,
            &next_modulo,
        );
        let mul_this_modulo = polymul_fast(
            &key.polynomial(),
            &iv.pow(self.block_count as usize + 1, &this_modulo), // TODO: pow((block_count * multiplicator) + 1)
            POLYNOMIAL_Q as i64,
            &this_modulo,
        );
        let mult_next_modulo = polysub(
            &mul_next_modulo,
            &mul_this_modulo,
            POLYNOMIAL_Q as i64,
            &next_modulo,
        );
        //println!("m({}) = {}", self.block_count, self.block_polynomial);
        //println!("mult: ({}) * ({})^{} mod ({}) - same mod ({})", key.polynomial(), iv.polynomial(), self.block_count + 1, next_modulo, this_modulo);
        EncryptedBlock::new(
            polyadd(
                &self.block_polynomial,
                &key.generate_encryption_polynomial(iv, self.block_count),
                POLYNOMIAL_Q as i64,
                key.get_modulus_polynomial(),
            ),
            mult_next_modulo,
            self.block_count,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn polynomial(&self) -> &Polynomial<i64> {
        &self.block_polynomial
    }
}

#[cfg(test)]
mod tests {
    use crate::plain_block::PlainBlock;

    #[test]
    fn test_plaintext_to_bytes() {
        const BYTES: &[u8; 8] = b"Hello, w";
        let plain_block = PlainBlock::from_bytes(BYTES, 0).unwrap();
        let bytes = plain_block.to_bytes();
        assert_eq!(BYTES, &bytes[..]);

        const BYTES2: &[u8; 16] = b"Hello, my world!";
        let plain_block = PlainBlock::from_bytes(BYTES2, 0).unwrap();
        let bytes = plain_block.to_bytes();
        assert_eq!(BYTES2, &bytes[..]);
    }
}
