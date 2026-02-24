#![forbid(unsafe_code)]
use crate::keccak::keccak;

mod keccak;

// TODO: remove code duplication. Use a macro?

pub fn sha3_224(message: &[u8]) -> [u8; 28] {
    let mut output = [0; 28];
    const CAPACITY: usize = 224 * 2;
    const RATE: usize = 1600 - CAPACITY;
    keccak(RATE, CAPACITY, message, &mut output);
    output
}

pub fn sha3_256(message: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    const CAPACITY: usize = 256 * 2;
    const RATE: usize = 1600 - CAPACITY;
    keccak(RATE, CAPACITY, message, &mut output);
    output
}

pub fn sha3_384(message: &[u8]) -> [u8; 48] {
    let mut output = [0; 48];
    const CAPACITY: usize = 384 * 2;
    const RATE: usize = 1600 - CAPACITY;
    keccak(RATE, CAPACITY, message, &mut output);
    output
}

pub fn sha3_512(message: &[u8]) -> [u8; 64] {
    let mut output = [0; 64];
    const CAPACITY: usize = 512 * 2;
    const RATE: usize = 1600 - CAPACITY;
    keccak(RATE, CAPACITY, message, &mut output);
    output
}

#[cfg(test)]
mod tests {
    use crate::sha3_256;

    #[test]
    fn can_hash() {
        let input = b"some input string";
        dbg!(sha3_256(&input[..]));
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
