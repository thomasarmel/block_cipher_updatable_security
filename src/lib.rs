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
    plaintext.chunks(security_level).enumerate().map(|(block_count, plain_block_bytes)| {
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