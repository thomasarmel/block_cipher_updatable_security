use block_cipher_updatable_security::Key;

fn main() {
    let key1 = Key::generate(128).unwrap();
    println!("Key1: {:?}", key1);
}
