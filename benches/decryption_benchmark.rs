use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use block_cipher_updatable_security::{decrypt, encrypt, Iv, Key};

fn criterion_benchmark(c: &mut Criterion) {
    const SMALL_PLAINTEXT: &[u8] = b"Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";
    const POEM_PLAINTEXT: &[u8] = include_bytes!("../src/data/poem.txt");

    let key = Key::generate(128, 0).unwrap();
    let iv = Iv::generate(256);

    let encrypt_small = encrypt(SMALL_PLAINTEXT, &key, &iv);
    let encrypt_poem = encrypt(POEM_PLAINTEXT, &key, &iv);

    c.bench_function("decrypt small", |b| b.iter(|| decrypt(black_box(&encrypt_small), &key, &iv)));
    c.bench_function("decrypt poem", |b| b.iter(|| decrypt(black_box(&encrypt_poem), &key, &iv)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);