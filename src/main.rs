use block_cipher_updatable_security::{encrypt, Key};

const PLAINTEXT: &[u8] = include_bytes!("data/plain1.txt");

fn main() {
    let key1 = Key::generate(128).unwrap();
    println!("Key1: {:?}", key1);
    let encrypted = encrypt(PLAINTEXT, &key1);
    println!("Encrypted: {:?}", encrypted);
}
