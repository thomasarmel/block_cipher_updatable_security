use block_cipher_updatable_security::{Iv, Key, encrypt, increase_security_level};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    const SMALL_PLAINTEXT: &[u8] =
        b"Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";
    const POEM_PLAINTEXT: &[u8] = include_bytes!("../src/data/poem.txt");

    let key = Key::generate(128, 0).unwrap();
    let iv = Iv::generate(256);
    let key2 = Key::generate(256, 1).unwrap();

    let encrypt_small = encrypt(SMALL_PLAINTEXT, &key, &iv);
    let encrypt_poem = encrypt(POEM_PLAINTEXT, &key, &iv);

    c.bench_function("increase security small", |b| {
        b.iter(|| increase_security_level(black_box(&encrypt_small), &iv, &key, &key2))
    });
    c.bench_function("increase security poem", |b| {
        b.iter(|| increase_security_level(black_box(&encrypt_poem), &iv, &key, &key2))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
