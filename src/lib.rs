extern crate core;

pub mod key;
pub mod error;
mod utils;
mod polynomial_algebra;

pub use key::Key;
pub use error::BlockCipherUpdatableSecurityError;

const POLYNOMIAL_Q: usize = 268409857;