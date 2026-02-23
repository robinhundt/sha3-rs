use crate::keccak::keccak;

mod keccak;

pub struct Digest([u8; 32]);

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
}
