# Post-quantum block cipher with key rotation and security level update

_Update the security level of the cipher without decrypting_

----

## Description

This is a post-quantum block cipher that allows for key rotation and security level updates without the need to decrypt the data.
The cipher is based on the Ring-LWE problem, which is believed to be secure against quantum attacks.

## API Documentation

#### Generate random Initialization Vector (IV):

<details>
<summary><code>fn Iv::generate(security_level: usize) -> Iv</code></summary>

> <code>security_level</code>: The security level of the cipher.
</details>

#### Generate random Key:
<details>
<summary><code>fn Key::generate(key_size_bits_security_level: usize, key_generation: usize) -> Key</code></summary>

> <code>key_size_bits_security_level</code>: The security level of the key.

> <code>key_generation</code>: The generation of the key: 0 if the key is used for first encryption of a cipher, then increment it for each key rotation.
</details>

#### Encrypt a message:
<details>
<summary><code>fn encrypt(plaintext: &[u8], key: &Key, iv: &Iv) -> Vec&lt;u8&gt;</code></summary>

> <code>plaintext</code>: The plaintext to encrypt.

> <code>key</code>: The key to use for encryption, its `key_generation` must be 0.

> <code>iv</code>: The initialization vector to use for encryption. It should be unique for each encryption, in order to ensure IND-CCA security.
</details>

#### Decrypt a message:
<details>
<summary><code>fn decrypt(ciphertext: &[u8], key: &Key, iv: &Iv) -> Vec&lt;u8&gt;</code></summary>

> <code>ciphertext</code>: The ciphertext to decrypt.

> <code>key</code>: The key to use for decryption.

> <code>iv</code>: The initialization vector to use for decryption.
</details>

#### Increase security level of a ciphertext:

<details>
<summary><code>fn increase_security_level(ciphertext: &[u8], iv: &Iv, old_key: &Key, new_key: &Key) -> Result&lt;Vec&lt;u8&gt;, BlockCipherUpdatableSecurityError&gt;</code></summary>

> <code>ciphertext</code>: The ciphertext to update.

> <code>iv</code>: The initialization vector that was used to encrypt the ciphertext.

> <code>old_key</code>: The old key that was used to encrypt the ciphertext.

> <code>new_key</code>: The new key to use for the updated ciphertext. Its `key_generation` must be incremented from the old key, and its security level must be greater than the old key.

Internally, the function will generate a security level upgrade token from the old key and the new key, and use it to update the ciphertext without decrypting it.
</details>


## Example

```rust
use block_cipher_updatable_security::{Iv, Key, decrypt, encrypt, increase_security_level};

const PLAINTEXT_TEXT: &'static str = "Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";
let plaintext = PLAINTEXT_TEXT.as_bytes();

println!("PLAIN: {}", PLAINTEXT_TEXT);
let iv = Iv::generate(256);
let key1 = Key::generate(128, 0).unwrap();
let encrypted = encrypt(plaintext, &key1, &iv);

let decrypted = decrypt(&encrypted, &key1, &iv);
let decrypted_text = std::str::from_utf8(&decrypted).unwrap()[..PLAINTEXT_TEXT.len()].to_string();
println!("Decrypted: {}", decrypted_text);
assert_eq!(PLAINTEXT_TEXT.to_string(), decrypted_text);

let key2 = Key::generate(256, 1).unwrap();
let encrypted2 = increase_security_level(&encrypted, &iv, &key1, &key2).unwrap();
let decrypted2 = decrypt(&encrypted2, &key2, &iv);
let decrypted2_text = std::str::from_utf8(&decrypted2).unwrap()[..PLAINTEXT_TEXT.len()].to_string();
println!("Decrypted2: {}", decrypted2_text);
assert_eq!(PLAINTEXT_TEXT.to_string(), decrypted2_text);

let key3 = Key::generate(512, 2).unwrap();
let encrypted3 = increase_security_level(&encrypted2, &iv, &key2, &key3).unwrap();
let decrypted3 = decrypt(&encrypted3, &key3, &iv);
let decrypted3_text = std::str::from_utf8(&decrypted3).unwrap()[..PLAINTEXT_TEXT.len()].to_string();
println!("Decrypted3: {}", decrypted3_text);
assert_eq!(PLAINTEXT_TEXT.to_string(), decrypted3_text);
```


## Test

You can launch the tests with the command:

```bash
cargo test
```

## Performance
You can test performance with the command:

```bash
cargo bench
```

Rerun the command after a code change to see how performance changed.


_(Code inspired from https://github.com/lattice-based-cryptography/ring-lwe)_
