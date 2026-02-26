use std::hint::black_box;

use haste::{Haste, Label};
use sha3::sha3_256;

fn main() {
    haste::main();
}

#[haste::bench]
fn bench_sha256(mut haste: Haste) {
    let sizes = [1024, 1024 * 1024];
    for size in sizes {
        let input = vec![0; size];
        haste
            .with_throughput(haste::Throughput::Bytes(size))
            .with_sample_count(50)
            .bench(Label::new("sha256").with_part(size), || {
                sha3_256(black_box(&input))
            });
    }
}

#[haste::bench]
fn bench_libcrux_sha256(mut haste: Haste) {
    let sizes = [1024, 1024 * 1024];
    for size in sizes {
        let input = vec![0; size];
        haste
            .with_throughput(haste::Throughput::Bytes(size))
            .with_sample_count(50)
            .bench(Label::new("libcrux sha256").with_part(size), || {
                libcrux_sha3::sha256(black_box(&input))
            });
    }
}
