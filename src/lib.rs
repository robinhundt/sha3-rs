//! SHA-3 Hash Functions
//!
//! This crate provides portable, pure Rust implementations of the SHA-3 hashing
//! functions standardized in [FIPS 202].
//!
//! # Limitations
//!
//! This software is intended as a learning exercise and not for production use.
//!
//! Performance has thus far not been a priority. This implementation is likely
//! orders of magnitude slower than optimized ones.
//!
//! We currently only expose functions to hash a complete byte slice `&[u8]`.
//! Individual bits or multiple inputs that update the hash are currently not
//! supported.
//!
//! The SHAKE128 and SHAKE256 extendable-output functions are available as
//! [`shake128`], [`shake256`] and the incremental [`Shake128`] and
//! [`Shake256`].
//!
//! # Example Usage
//! ```
//! # use sha3::sha3_256;
//! #
//! let message = b"your input bytes";
//! let hash: [u8; 32] = sha3_256(message);
//! let expected = "414d4b6d11a92aaeeebe35f9374942f563848d345631bf5537407252dca6b378";
//! assert_eq!(expected, hex::encode(hash))
//! ```
//!
//! [FIPS 202]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

pub mod hasher;
mod permute;
mod sponge;
pub mod xof;

pub use const_array;
pub use hasher::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub use xof::{Shake128, Shake256};

// TODO: remove code duplication. Use a macro?

/// SHA-3 Hash with 224 bits (28 bytes) output.
pub fn sha3_224(msg: &[u8]) -> [u8; 28] {
    let mut hasher = Sha3_224::new();
    hasher.update(msg);
    hasher.finalize().into_array()
}

/// SHA-3 Hash with 256 bits (32 bytes) output.
pub fn sha3_256(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(msg);
    hasher.finalize().into_array()
}

/// SHA-3 Hash with 384 bits (48 bytes) output.
pub fn sha3_384(msg: &[u8]) -> [u8; 48] {
    let mut hasher = Sha3_384::new();
    hasher.update(msg);
    hasher.finalize().into_array()
}

/// SHA-3 Hash with 512 bits (64 bytes) output.
pub fn sha3_512(msg: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(msg);
    hasher.finalize().into_array()
}

/// SHAKE128 extendable-output function. Fills `output` completely.
pub fn shake128(msg: &[u8], output: &mut [u8]) {
    let mut xof = Shake128::new();
    xof.update(msg);
    xof.finalize().squeeze(output);
}

/// SHAKE256 extendable-output function. Fills `output` completely.
pub fn shake256(msg: &[u8], output: &mut [u8]) {
    let mut xof = Shake256::new();
    xof.update(msg);
    xof.finalize().squeeze(output);
}

#[cfg(test)]
mod tests {

    use crate::{sha3_256, shake128, shake256};

    #[test]
    fn can_hash() {
        let input = b"some input string";
        sha3_256(&input[..]);
    }

    #[cfg(not(miri))]
    #[test]
    fn compare_to_libcrux() {
        // Go beyond one block
        for i in 0..300 {
            let input = vec![0; i];
            let my_hash = sha3_256(&input[..]);
            let other_hash = libcrux_sha3::sha256(&input);
            assert_eq!(my_hash, other_hash.as_slice(), "len {i} hash differs");
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn compare_shake_to_libcrux() {
        let input = [42; 300];
        // Output lengths around the rates of 168 (SHAKE128) and 136 (SHAKE256)
        // bytes
        for out_len in [0, 1, 32, 135, 136, 137, 167, 168, 169, 400] {
            for in_len in [0, 1, 135, 136, 137, 167, 168, 169, 300] {
                let mut out = vec![0; out_len];
                let mut expected = vec![0; out_len];
                shake128(&input[..in_len], &mut out);
                libcrux_sha3::shake128_ema(&mut expected, &input[..in_len]);
                assert_eq!(expected, out, "shake128 in {in_len} out {out_len}");
                shake256(&input[..in_len], &mut out);
                libcrux_sha3::shake256_ema(&mut expected, &input[..in_len]);
                assert_eq!(expected, out, "shake256 in {in_len} out {out_len}");
            }
        }
    }
}
