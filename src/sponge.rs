//! KECCAK Sponge construction with incremental API.
use crate::permute::State;

/// Absorb bytes into the Keccakf[1600] state.
pub(crate) struct Absorb<const RATE_BYTES: usize> {
    pos: usize,
    state: State<RATE_BYTES>,
}

impl<const RATE_BYTES: usize> Absorb<RATE_BYTES> {
    pub(crate) fn new() -> Self {
        Self {
            state: State::new(),
            pos: 0,
        }
    }

    pub(crate) fn absorb(&mut self, msg: &[u8]) {
        // first, we handle a potentially partial block, either due to and advanced
        // position or msg.len() < RATE_BYTES
        let partial_block_len = (RATE_BYTES - self.pos).min(msg.len());
        let (first_msg, rest_msg) = msg.split_at(partial_block_len);
        xor_bytes(&mut self.state.bytes_mut()[self.pos..], first_msg);
        // if the state was filled, we permute and reset the position
        if self.pos + partial_block_len == RATE_BYTES {
            self.state.keccakf_1600_permute();
            self.pos = 0;
        } else {
            // otherwise, we increment the position.
            self.pos += partial_block_len;
            // this branch is only taken if self.pos + partial_block_len < RATE_BYTES, so
            // we know that rest_msg.is_empty() and can safely return
            debug_assert!(rest_msg.is_empty());
            return;
        }

        // Absorb the remaining message
        let (chunks, rest) = rest_msg.as_chunks::<RATE_BYTES>();
        for chunk in chunks {
            xor_bytes(self.state.bytes_mut(), chunk);
            self.state.keccakf_1600_permute();
        }
        self.pos = rest.len();
        xor_bytes(self.state.bytes_mut(), rest);
    }

    /// Add domain separator and padding and turn into [`Squeeze`].
    ///
    /// Note that this performs no permute! Contrary to to FIPS202, we define
    /// the squeezing phase to start with a permutation (instead of ending
    /// the absorption with a permutation).
    pub(crate) fn into_squeeze<const DELIMETED_SUFFIX: u8>(mut self) -> Squeeze<RATE_BYTES> {
        let state_bytes = self.state.bytes_mut();
        state_bytes[self.pos] ^= DELIMETED_SUFFIX;
        state_bytes[RATE_BYTES - 1] ^= 0b10000000_u8;
        Squeeze::new(self.state)
    }
}

/// Squeeze bytes from the Keccakf[1600] state.
pub(crate) struct Squeeze<const RATE_BYTES: usize> {
    pos: usize,
    state: State<RATE_BYTES>,
}

impl<const RATE_BYTES: usize> Squeeze<RATE_BYTES> {
    fn new(state: State<RATE_BYTES>) -> Self {
        Self { pos: 0, state }
    }

    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }

        if self.pos == 0 {
            self.state.keccakf_1600_permute();
        }
        let partial_block_len = (RATE_BYTES - self.pos).min(output.len());
        let (first_output, rest_output) = output.split_at_mut(partial_block_len);
        first_output.copy_from_slice(&self.state.bytes()[self.pos..self.pos + partial_block_len]);
        self.pos = (self.pos + partial_block_len) % RATE_BYTES;
        if rest_output.is_empty() {
            return;
        }

        let (chunks, rest) = rest_output.as_chunks_mut::<RATE_BYTES>();
        for chunk in chunks {
            self.state.keccakf_1600_permute();
            chunk.copy_from_slice(&self.state.bytes()[..RATE_BYTES]);
        }
        self.pos = rest.len();
        rest.copy_from_slice(&self.state.bytes()[..self.pos]);
    }
}

fn xor_bytes(dest: &mut [u8], other: &[u8]) {
    // for_each combinator can lead to better codegen
    dest.iter_mut().zip(other).for_each(|(state, input)| {
        *state ^= input;
    });
}

#[cfg(test)]
mod tests {
    use crate::sponge::Absorb;

    #[test]
    fn partial_absorb() {
        const RATE_BYTES_SHA_256: usize = 136;
        let sizes: Vec<Vec<usize>> = vec![
            vec![0],
            vec![0, 0],
            vec![0, 30],
            vec![0, 30, 200],
            vec![30, 200],
            vec![RATE_BYTES_SHA_256, 200],
            vec![40, RATE_BYTES_SHA_256 - 40],
            vec![40, RATE_BYTES_SHA_256 - 40, 30],
            vec![40, RATE_BYTES_SHA_256 - 40, 30, 0, 20],
            vec![15, 20, 40, RATE_BYTES_SHA_256 - 15 - 20 - 40, 20],
        ];
        for msg_sizes in sizes {
            let mut absorb = Absorb::<RATE_BYTES_SHA_256>::new();
            let msgs: Vec<_> = msg_sizes.iter().map(|size| vec![0; *size]).collect();
            let complete_msg = vec![0; msg_sizes.iter().sum()];
            for msg in &msgs {
                absorb.absorb(msg);
            }
            let mut squeeze = absorb.into_squeeze::<0b110_u8>();
            let mut output = [0; 32];
            squeeze.squeeze(&mut output);
            let expected = libcrux_sha3::sha256(&complete_msg);
            assert_eq!(
                expected, output,
                "{msg_sizes:?}, msgs: {msgs:?} complete: {complete_msg:?}"
            );
        }
    }
}
