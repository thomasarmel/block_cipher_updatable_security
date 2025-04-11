use block_cipher_updatable_security::{Iv, Key, decrypt, encrypt, increase_security_level};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::Write;
use polynomial_ring::polynomial;

//const PLAINTEXT: &[u8] = include_bytes!("data/poem.txt");
const PLAINTEXT: &[u8] = b"Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";

fn main() {
    let iv = Iv::generate(256);
    let key1 = Key::generate(128, 0).unwrap();
    //println!("Key1: {:?}", key1);
    let start = std::time::Instant::now();
    let encrypted = encrypt(PLAINTEXT, &key1, &iv);
    let elapsed = start.elapsed();
    println!("Encryption took: {:?}", elapsed);
    //println!("Encrypted: {}", encrypted.len());
    //println!("PLAIN: {:?}", PLAINTEXT);
    let decrypted = decrypt(&encrypted, &key1, &iv);
    println!("Plaintext: {:?}", PLAINTEXT);
    //println!("Decrypted: {:?}", &decrypted);
    println!("Decrypted: {:?}", std::str::from_utf8(&decrypted).unwrap());

    let key2 = Key::generate(256, 1).unwrap();
    let start = std::time::Instant::now();
    let encrypted2 = increase_security_level(&encrypted, &iv, &key1, &key2).unwrap();
    let elapsed = start.elapsed();
    println!("Security level increase took: {:?}", elapsed);
    let decrypted2 = decrypt(&encrypted2, &key2, &iv);
    println!("Decrypted2: {:?}", decrypted2);
    println!("Decrypted2: {}", std::str::from_utf8(&decrypted2).unwrap());

    let key3 = Key::generate(512, 2).unwrap();
    let start = std::time::Instant::now();
    let encrypted3 = increase_security_level(&encrypted2, &iv, &key2, &key3).unwrap();
    let elapsed = start.elapsed();
    println!("Security level increase took: {:?}", elapsed);
    let decrypted3 = decrypt(&encrypted3, &key3, &iv);
    println!("Decrypted3: {:?}", decrypted3);
    println!("Decrypted3: {}", std::str::from_utf8(&decrypted3).unwrap());

    /*println!("Plain: {}", PLAINTEXT.len());
    println!(
        "Encrypted {} (x {})",
        encrypted.len(),
        encrypted.len() / PLAINTEXT.len()
    );
    let mut e = ZlibEncoder::new(Vec::new(), Compression::new(9));
    e.write_all(&encrypted);
    let compressed_bytes = e.finish().unwrap();
    println!(
        "Compressed: {} (x {})",
        compressed_bytes.len(),
        compressed_bytes.len() / PLAINTEXT.len()
    );*/
}
