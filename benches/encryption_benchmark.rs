use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use block_cipher_updatable_security::{encrypt, Iv, Key};

fn criterion_benchmark(c: &mut Criterion) {
    const SMALL_PLAINTEXT: &[u8] = b"Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!";
    const POEM_PLAINTEXT: &[u8] = include_bytes!("../src/data/poem.txt");

    let key = Key::generate(128, 0).unwrap();
    let iv = Iv::generate(256);

    c.bench_function("encrypt small", |b| b.iter(|| encrypt(black_box(SMALL_PLAINTEXT), &key, &iv)));
    c.bench_function("encrypt poem", |b| b.iter(|| encrypt(black_box(POEM_PLAINTEXT), &key, &iv)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);