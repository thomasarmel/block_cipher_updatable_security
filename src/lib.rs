extern crate core;

pub mod key;
pub mod error;
mod utils;
mod polynomial_algebra;
mod plain_block;
mod encrypted_block;

pub use key::Key;
pub use error::BlockCipherUpdatableSecurityError;
use crate::plain_block::PlainBlock;

const POLYNOMIAL_Q: usize = 268409857;

pub fn encrypt(plaintext: &[u8], key: &Key) -> Vec<u8> {
    let security_level = key.security_level();
    plaintext.chunks(security_level / 8).enumerate().map(|(block_count, plain_block_bytes)| {
        let mut padded_bytes = vec![0u8; security_level];
        let plain_block_bytes = if plain_block_bytes.len() == security_level {
            plain_block_bytes
        } else {
            padded_bytes[..plain_block_bytes.len()].copy_from_slice(plain_block_bytes);
            &*padded_bytes
        };
        let plain_block = PlainBlock::from_bytes(plain_block_bytes, block_count as u64).unwrap();
        plain_block.encrypt(key).to_bytes()
    }).flatten().collect()
}

pub fn decrypt(ciphertext: &[u8], key: &Key) -> Vec<u8> {
    let security_level = key.security_level();
    ciphertext.chunks(security_level * 8).enumerate().map(|(block_count, encrypted_block_bytes)| {
        let encrypted_block = encrypted_block::EncryptedBlock::from_bytes(encrypted_block_bytes, block_count as u64);
        let plain_block = encrypted_block.decrypt(key);
        plain_block.to_bytes()
    }).flatten().collect()
}


#[cfg(test)]
mod tests {
    use crate::{decrypt, encrypt, Key};

    #[test]
    fn test_encrypt_decrypt_large() {
        const PLAINTEXT: &[u8] = include_bytes!("data/poem.txt");
        const SECURITY_LEVEL: usize = 128;
        let key1 = Key::generate(SECURITY_LEVEL).unwrap();
        let encrypted = encrypt(PLAINTEXT, &key1);
        let decrypted = decrypt(&encrypted, &key1);
        assert_eq!(*PLAINTEXT, decrypted[0..PLAINTEXT.len()]);
    }
}