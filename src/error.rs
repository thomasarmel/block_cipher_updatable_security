use thiserror::Error;

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlockCipherUpdatableSecurityError {
    #[error("Invalid key size: must be a power of 2, and >= 128 bits")]
    InvalidKeySize,
    #[error("Invalid input block size: must be a non null power of 2")]
    InvalidBlockSize,
}