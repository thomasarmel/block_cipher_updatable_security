pub mod key;
pub mod error;
mod utils;

pub use key::Key;
pub use error::BlockCipherUpdatableSecurityError;

const POLYNOMIAL_Q: usize = 268409857;