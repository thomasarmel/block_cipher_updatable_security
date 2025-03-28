use block_cipher_updatable_security::{decrypt, encrypt, Key};

const PLAINTEXT: &[u8] = include_bytes!("data/poem.txt");

fn main() {
    let key1 = Key::generate(128).unwrap();
    //println!("Key1: {:?}", key1);
    let encrypted = encrypt(PLAINTEXT, &key1);
    println!("Encrypted: {}", encrypted.len());
    //println!("Encrypted: {:?}", encrypted);
    let decrypted = decrypt(&encrypted, &key1);
    println!("Plaintext: {:?}", PLAINTEXT);
    println!("Decrypted: {:?}", &decrypted);
    println!("Decrypted: {:?}", std::str::from_utf8(&decrypted).unwrap());
}
