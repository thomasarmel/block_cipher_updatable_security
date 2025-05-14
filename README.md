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
<summary><code>fn encrypt(plaintext: &[u8], key: &Key, iv: &Iv) -> Vec<u8></code></summary>

> <code>plaintext</code>: The plaintext to encrypt.

> <code>key</code>: The key to use for encryption, its `key_generation` must be 0.

> <code>iv</code>: The initialization vector to use for encryption. It should be unique for each encryption, in order to ensure IND-CCA security.
</details>

#### Decrypt a message:
<details>
<summary><code>fn decrypt(ciphertext: &[u8], key: &Key, iv: &Iv) -> Vec\<u8\></code></summary>

> <code>ciphertext</code>: The ciphertext to decrypt.

> <code>key</code>: The key to use for decryption.

> <code>iv</code>: The initialization vector to use for decryption.
</details>

#### Increase security level of a ciphertext:

<details>
<summary><code>fn increase_security_level(ciphertext: &[u8], iv: &Iv, old_key: &Key, new_key: &Key) -> Result\<Vec\<u8\>, BlockCipherUpdatableSecurityError\></code></summary>

</details>


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