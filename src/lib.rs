use crate::keccak::keccak;

mod keccak;

pub struct Digest(pub [u8; 32]);

pub fn sha3_256(message: &[u8]) -> Digest {
    let mut output = [0; 32];
    keccak(1088, 512, message, &mut output);
    Digest(output)
}

#[cfg(test)]
mod tests {
    use crate::sha3_256;

    #[test]
    fn can_hash() {
        let input = b"some input string";
        dbg!(sha3_256(&input[..]).0);
    }

    #[cfg(not(miri))]
    #[test]
    fn compare_to_libcrux() {
        // Go beyond one block
        for i in 0..300 {
            let input = vec![0; i];
            let my_hash = sha3_256(&input[..]);
            let other_hash = libcrux_sha3::sha256(&input);
            assert_eq!(my_hash.0, other_hash.as_slice(), "len {i} hash differs");
        }
    }
}
