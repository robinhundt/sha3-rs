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
//! We currently do not implement the SHAKE extendable-output functions
//! described in [FIPS 202].
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

pub use hasher::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

// TODO: remove code duplication. Use a macro?

/// SHA-3 Hash with 224 bits (28 bytes) output.
pub fn sha3_224(msg: &[u8]) -> [u8; 28] {
    let mut hasher = Sha3_224::new();
    hasher.update(msg);
    hasher.finalize()
}

/// SHA-3 Hash with 256 bits (32 bytes) output.
pub fn sha3_256(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(msg);
    hasher.finalize()
}

/// SHA-3 Hash with 384 bits (48 bytes) output.
pub fn sha3_384(msg: &[u8]) -> [u8; 48] {
    let mut hasher = Sha3_384::new();
    hasher.update(msg);
    hasher.finalize()
}

/// SHA-3 Hash with 512 bits (64 bytes) output.
pub fn sha3_512(msg: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(msg);
    hasher.finalize()
}

#[cfg(test)]
mod tests {

    use crate::sha3_256;

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
}
