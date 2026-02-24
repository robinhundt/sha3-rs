# SHA-3 in Rust
[![docs](https://img.shields.io/badge/docs-main-brightgreen)](https://robinhundt.github.io/sha3-rs/sha3/)
[![CI](https://github.com/robinhundt/sha3-rs/actions/workflows/push.yml/badge.svg)](https://github.com/robinhundt/sha3-rs/actions/workflows/push.yml)

> [!CAUTION]  
> This implementation is intended for learning purposes and not ready for production use cases.

This repository provides a portable and pure Rust implementation of the SHA-3 hashing functions ([FIPS 202]).

The implementation is largely based on those contained in the [XKCP] repository from the Keccak Team. The largest influences are the [readable and compact] and the [ref-64-bits] implementations. I purposely did not refer to other Rust implementations of SHA-3 to not be biased by their choices and determine how hard it would be to implement SHA-3 from the reference implementations in another language (C) and the [FIPS 202] standard.  
An implementation intended for production should definitely take learnings from a broader set of implementations (including those in Rust, e.g. [libcrux-sha3], [sha3]).

## Platform support
This crate is tested in CI to work on the GitHub `ubuntu-latest` (x86-64), `windows-latest` (x86-64) and `macos-latest` (arm64) runners. Additionally, we run the test suite on a QEMU emulated `s390-unknown-linux-gnu` target using [cross] in CI, to test support on big-endian systems.

## Testing

Run `cargo test` to test this implementation against [libcrux-sha3] for a small number of messages and the byte-oriented [test vectors] provided by NIST as part of FIPS 202.

[FIPS 202]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
[readable and compact]: https://github.com/XKCP/XKCP/blob/716f007dd73ef28d357b8162173646be574ad1b7/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
[ref-64-bits]: https://github.com/XKCP/XKCP/tree/716f007dd73ef28d357b8162173646be574ad1b7/lib/low/KeccakP-1600/ref-64bits
[XKCP]: https://github.com/XKCP/XKCP
[libcrux-sha3]: https://crates.io/crates/libcrux-sha3
[sha3]: https://crates.io/crates/sha3
[test vectors]: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss
[cross]: https://github.com/cross-rs/cross