extern crate core;

mod encrypted_block;
pub mod error;
mod irreducible_modulos;
pub mod iv;
pub mod key;
mod plain_block;
mod polynomial_algebra;
mod utils;

use crate::encrypted_block::EncryptedBlock;
use crate::plain_block::PlainBlock;
use crate::polynomial_algebra::{polyadd, polymul_fast, polysub};
use crate::utils::generate_merging_block_polynomial;
pub use error::BlockCipherUpdatableSecurityError;
pub use iv::Iv;
pub use key::Key;
use polynomial_ring::Polynomial;
use rand_distr::num_traits::{One, Zero};

// POLYNOMIAL_Q is prime
// POLYNOMIAL_Q - 1 mod (2^15) = 0
const POLYNOMIAL_Q: usize = 945586177;

pub fn encrypt(plaintext: &[u8], key: &Key, iv: &Iv) -> Vec<u8> {
    let security_level = key.security_level();
    let cipher_blocks: Vec<EncryptedBlock> = plaintext
        .chunks(security_level / 8)
        .enumerate()
        .map(|(block_count, plain_block_bytes)| {
            let mut padded_bytes = vec![0u8; security_level];
            let plain_block_bytes = if plain_block_bytes.len() == security_level {
                plain_block_bytes
            } else {
                padded_bytes[..plain_block_bytes.len()].copy_from_slice(plain_block_bytes);
                &*padded_bytes
            };
            let plain_block =
                PlainBlock::from_bytes(plain_block_bytes, block_count as u64).unwrap();
            plain_block.encrypt(key, iv)
        })
        .collect();
    serde_cbor::to_vec(&cipher_blocks).unwrap()
}

pub fn decrypt(ciphertext: &[u8], key: &Key, iv: &Iv) -> Vec<u8> {
    let cipher_blocks: Vec<EncryptedBlock> = serde_cbor::from_slice(ciphertext).unwrap();
    cipher_blocks
        .iter()
        .map(|cipher_block| {
            let plain_block = cipher_block.decrypt(key, iv);
            plain_block.to_bytes()
        })
        .flatten()
        .collect()
}

pub fn increase_security_level(
    ciphertext: &[u8],
    iv: &Iv,
    old_key: &Key,
    new_key: &Key,
) -> Result<Vec<u8>, BlockCipherUpdatableSecurityError> {
    // random padding is ok
    let old_security_level = old_key.security_level();
    let new_security_level = new_key.security_level();
    if new_security_level != old_security_level * 2 {
        return Err(BlockCipherUpdatableSecurityError::InvalidNewKeySecurityLevel);
    }

    let temp_key_polynomial = polymul_fast(
        &polyadd(
            &polymul_fast(
                &iv.pow(1 << old_key.key_generation(), new_key.get_modulus_polynomial()),
                &generate_merging_block_polynomial(old_security_level),
                POLYNOMIAL_Q as i64,
                new_key.get_modulus_polynomial(),
            ),
            &Polynomial::one(),
            POLYNOMIAL_Q as i64,
            new_key.get_modulus_polynomial(),
        ),
        &old_key.polynomial(),
        POLYNOMIAL_Q as i64,
        new_key.get_modulus_polynomial(),
    );

    let cipher_blocks: Vec<EncryptedBlock> = serde_cbor::from_slice(ciphertext).unwrap();

    let new_cipher_blocks: Vec<EncryptedBlock> = cipher_blocks
        .chunks(2)
        .enumerate()
        .map(|(new_block_count, encrypted_blocks_bytes)| {
            let mut encrypted_blocks_bytes = encrypted_blocks_bytes.to_vec();
            if encrypted_blocks_bytes.len() == 1 {
                let null_bytes = vec![0u8; old_security_level >> 3];
                let null_plain_block = PlainBlock::from_bytes(&null_bytes, encrypted_blocks_bytes[0].block_count() + 1).unwrap();
                let null_encrypted_block = null_plain_block.encrypt(old_key, iv);
                encrypted_blocks_bytes.push(null_encrypted_block);
            }

            let (even_block, odd_block) = (&encrypted_blocks_bytes[0], &encrypted_blocks_bytes[1]);
            let expanded_block = polyadd(
                &polymul_fast(
                    &polyadd(&odd_block.enc_polynomial(), &odd_block.mul_polynomial(), POLYNOMIAL_Q as i64, new_key.get_modulus_polynomial()),
                    &generate_merging_block_polynomial(old_security_level),
                    POLYNOMIAL_Q as i64,
                    new_key.get_modulus_polynomial(),
                ),
                &polyadd(&even_block.enc_polynomial(), &even_block.mul_polynomial(), POLYNOMIAL_Q as i64, new_key.get_modulus_polynomial()),
                POLYNOMIAL_Q as i64,
                new_key.get_modulus_polynomial(),
            );
            (new_block_count, expanded_block)
        })
        .map(|(super_block_count, temp_polynomial)| {
            let new_key_factor =
                new_key.generate_encryption_factor_polynomial(iv, super_block_count as u64);
            let temp_key_factor = polymul_fast(
                &iv.pow((super_block_count << new_key.key_generation()) + 1, new_key.get_modulus_polynomial()),
                &temp_key_polynomial,
                POLYNOMIAL_Q as i64,
                new_key.get_modulus_polynomial(),
            );
            let delta = polysub(
                &new_key_factor,
                &temp_key_factor,
                POLYNOMIAL_Q as i64,
                new_key.get_modulus_polynomial(),
            );
            EncryptedBlock::new(
                polyadd(
                    &temp_polynomial,
                    &delta,
                    POLYNOMIAL_Q as i64,
                    new_key.get_modulus_polynomial(),
                ),
                new_key.prepare_next_multiplier(iv, super_block_count),
                super_block_count as u64,
            )
        })
        .collect();

    Ok(serde_cbor::to_vec(&new_cipher_blocks).unwrap())
}

#[cfg(test)]
mod tests {
    use crate::{decrypt, encrypt, increase_security_level, Iv, Key};

    #[test]
    fn test_encrypt_decrypt_large() {
        const PLAINTEXT: &[u8] = include_bytes!("data/poem.txt");
        const SECURITY_LEVEL: usize = 128;
        let iv = Iv::generate(SECURITY_LEVEL);
        let key1 = Key::generate(SECURITY_LEVEL, 0).unwrap();
        let encrypted = encrypt(PLAINTEXT, &key1, &iv);

        let decrypted = decrypt(&encrypted, &key1, &iv);
        assert_eq!(*PLAINTEXT, decrypted[0..PLAINTEXT.len()]);
    }

    #[test]
    fn test_reencryption() {
        const PLAINTEXT: &'static str = "Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";
        const INITIAL_KEY_SECURITY_LEVEL: usize = 128;
        const IV_SECURITY_LEVEL: usize = 256;
        let plain_bytes = PLAINTEXT.as_bytes();

        let iv = Iv::generate(IV_SECURITY_LEVEL);
        let key1 = Key::generate(INITIAL_KEY_SECURITY_LEVEL, 0).unwrap();
        let encrypted = encrypt(plain_bytes, &key1, &iv);
        let decrypted = decrypt(&encrypted, &key1, &iv);
        let decrypted_text = std::str::from_utf8(&decrypted).unwrap()[..PLAINTEXT.len()].to_string();
        assert_eq!(PLAINTEXT.to_string(), decrypted_text.to_string());

        let key2 = Key::generate(INITIAL_KEY_SECURITY_LEVEL * 2, 1).unwrap();
        let encrypted2 = increase_security_level(&encrypted, &iv, &key1, &key2).unwrap();
        let decrypted2 = decrypt(&encrypted2, &key2, &iv);
        let decrypted2_text = std::str::from_utf8(&decrypted2).unwrap()[..PLAINTEXT.len()].to_string();
        assert_eq!(PLAINTEXT.to_string(), decrypted2_text.to_string());
    }
}
