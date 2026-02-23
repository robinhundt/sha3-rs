//! SHA-3 implementation based on [Keccak-readable-and-compact.c]
//!
//! This implementation of SHA-3 is closely based on the readable and compact
//! implementation of the Keccak Team. It is currently written in slightly
//! unidiomatic rust to closely adhere to the linked reference implementation.
//!
//! [Keccak-readable-and-compact.c]: https://github.com/XKCP/XKCP/blob/716f007dd73ef28d357b8162173646be574ad1b7/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
#![allow(non_snake_case)]
use std::{cmp, mem};

/// Bits that are appended to the end of the input for domain separation and
/// padding. For SHA-3, this is the bit pattern 0b10 + the first 1 bit of the
/// pad10*1 padding.
const DELIMETED_SUFFIX: u8 = 0b110;

type State = [u8; 200];
type Lane = u64;

fn i(x: usize, y: usize) -> usize {
    mem::size_of::<Lane>() * (x + 5 * y)
}

// Notes for read/write/xor_lane:
// These could be optimized by having state be u64 aligned so that we
// can directly store/load/xor lanes on LE architectures.

fn read_lane(x: usize, y: usize, state: &State) -> Lane {
    let start = i(x, y);
    // TODO check whether this optimizes to a simple unaligned load
    //  potentially optimize this by hand. The slice index is likely
    //  not optimized out
    let bytes = state[start..start + 8]
        .try_into()
        // Very likely to be optimized out
        .expect("slice has length 8");
    Lane::from_le_bytes(bytes)
}

fn write_lane(x: usize, y: usize, lane: Lane, state: &mut State) {
    // TODO does this properly optimize on an LE architecture?
    let bytes = lane.to_le_bytes();
    let start = i(x, y);
    state[start..start + 8].copy_from_slice(&bytes);
}

fn xor_lane(x: usize, y: usize, lane: Lane, state: &mut State) {
    // TODO Unlikely that this properly optimizes on LE arches
    //  If the state where u64 aligned, this would be much more efficient
    let bytes = lane.to_le_bytes();
    let start = i(x, y);
    for (state_byte, byte) in state[start..start + 8].iter_mut().zip(bytes) {
        *state_byte ^= byte
    }
}

// TODO return type? int in c code
fn lfsr_86540(state: &mut u8) -> i32 {
    let result = i32::from((*state & 0x01) != 0);
    if (*state & 0x80) != 0 {
        *state = (*state << 1) ^ 0x71;
    } else {
        *state <<= 1;
    }
    result
}

fn keccakf_1600_state_permute(state: &mut State) {
    let mut lfsr_state = 0x01;

    for _round in 0..24 {
        {
            // θ step (Algorithm 1 θ(A))
            let mut C: [Lane; 5] = Default::default();
            // Step 1
            // Computes the parity of the columns
            for (x, Cx) in C.iter_mut().enumerate() {
                for y in 0..5 {
                    *Cx ^= read_lane(x, y, state)
                }
            }

            // Step 2
            for x in 0..5 {
                // Compute the θ effect for a given column
                // (x + 4) % 5 is equivalent to (x - 1) % 5 in the spec
                let D = C[(x + 4) % 5] ^ C[(x + 1) % 5].rotate_left(1);
                // Add the θ effect to the whole column
                for y in 0..5 {
                    xor_lane(x, y, D, state);
                }
            }
        }

        {
            // Combined ρ and π steps (see 3.2.2 and 3.2.3 of FIPS202)
            // Quote from 3.2.2 (description of ρ):
            // > The effect of ρ is to rotate the bits of each lane by a length, called the
            // > offset, which depends on the fixed x and y coordinates of the
            // > lane. Equivalently, for each bit in the lane, the z coordinate is
            // > modified by adding the offset, modulo the lane size.
            // Quote from 3.2.3 (description of π):
            // > The effect of π is to rearrange the positions of the lanes, as illustrated for any slice in Figure 5
            // > below.
            // Step 2: Start at (1, 0)
            let mut x = 1;
            let mut y = 0;
            let mut current = read_lane(x, y, state);
            for t in 0..24 {
                // Compute the rotation constant r = (t + 1)(t + 2)/2
                let r = ((t + 1) * (t + 2) / 2) % 64;
                // Step 3.b
                let Y = (2 * x + 3 * y) % 5;
                x = y;
                y = Y;
                let temp = read_lane(x, y, state);
                write_lane(x, y, current.rotate_left(r), state);
                current = temp;
            }
        }

        {
            // χ step (see 3.2.4)
            let mut temp: [Lane; 5] = Default::default();
            for y in 0..5 {
                // copy the plane
                for (x, tempx) in temp.iter_mut().enumerate() {
                    *tempx = read_lane(x, y, state)
                }
                // compute χ on the plane
                for x in 0..5 {
                    let chi = temp[x] ^ ((!temp[(x + 1) % 5]) & temp[(x + 2) % 5]);
                    write_lane(x, y, chi, state);
                }
            }
        }

        {
            // ι step (see 3.2.5)
            for j in 0..7 {
                // 2^j - 1
                let bit_position = (1 << j) - 1;
                if lfsr_86540(&mut lfsr_state) != 0 {
                    xor_lane(0, 0, 1 << bit_position, state);
                }
            }
        }
    }
}

pub(crate) fn keccak(rate: usize, capacity: usize, mut input: &[u8], mut output: &mut [u8]) {
    let mut state = [0_u8; 200];
    let rate_in_bytes = rate / 8;
    let mut block_size = 0;

    assert_eq!(1600, rate + capacity);
    assert_eq!(0, rate % 8);

    let mut input_byte_len = input.len();

    // Absorb input blocks
    while input_byte_len > 0 {
        block_size = cmp::min(input_byte_len, rate_in_bytes);
        for (state_i, input_i) in state[..block_size].iter_mut().zip(input) {
            *state_i ^= input_i;
        }
        input = &input[block_size..];
        input_byte_len -= block_size;

        if block_size == rate_in_bytes {
            keccakf_1600_state_permute(&mut state);
            block_size = 0;
        }
    }

    state[block_size] ^= DELIMETED_SUFFIX;
    // Add second bit of padding
    state[rate_in_bytes - 1] ^= 0b10000000_u8;

    // squeezing phase
    keccakf_1600_state_permute(&mut state);

    let mut output_byte_len = output.len();
    while output_byte_len > 0 {
        let block_size = cmp::min(output_byte_len, rate_in_bytes);
        output.copy_from_slice(&state[..block_size]);
        output = &mut output[block_size..];
        output_byte_len -= block_size;

        if output_byte_len > 0 {
            keccakf_1600_state_permute(&mut state);
        }
    }
}
