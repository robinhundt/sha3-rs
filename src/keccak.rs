//! SHA-3 implementation based on [XKCP]
//!
//! This implementation of SHA-3 is based on the [readable and compact]
//! and the [ref-64-bits] implementations of the Keccak Team. It is currently
//! written in slightly unidiomatic rust to closely adhere to the linked
//! reference implementation.
//!
//! [readable and compact]: https://github.com/XKCP/XKCP/blob/716f007dd73ef28d357b8162173646be574ad1b7/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
//! [ref-64-bits]: https://github.com/XKCP/XKCP/tree/716f007dd73ef28d357b8162173646be574ad1b7/lib/low/KeccakP-1600/ref-64bits
//! [XKCP]: https://github.com/XKCP/XKCP
#![allow(non_snake_case)]
use std::{cmp, mem};

// NOTE: References to Sections, Algorithms, Tables, etc. refer to the
// FIPS 202 standard (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
// if not otherwise specified.

/// Bits that are appended to the end of the input for domain separation and
/// padding. For SHA-3, this is the bit pattern 0b10 + the first 1 bit of the
/// pad10*1 padding.
const DELIMETED_SUFFIX: u8 = 0b110;

const ROUNDS: usize = 24;

/// State array A. Contains 1600 bits.
#[derive(Clone, Copy)]
struct State {
    // TODO: Can we use [u64; 25] without needing unsafe or bytemuck/zerocopy?
    bytes: [u8; 200],
}

/// Lane of the [`State`] array containing w = 64 bits.
type Lane = u64;

/// Compute a [`Lane`] index if viewing the [`State`] as `[u64; 25]`.
///
/// Note that this does not give you the start byte of a lane in the actual
/// [`State`]. For that, use [`lane_start_byte`].
fn idx(x: usize, y: usize) -> usize {
    // TODO: As in the XKCP/lib/low/KeccakP-1600/ref-64bits/KeccakP-1600-reference.c
    //  reference implementation, this always performs the modulo operation.
    //  Does the compiler remove this operation in cases where it is note necessary,
    //  e.g. when x and y come from bounded loops?
    (x % 5) + 5 * (y % 5)
}

/// Start byte of a [`Lane`] in the [`State`].
///
/// The [`Lane`] is located at the 8 bytes starting from the position returned
/// by this function.
fn lane_start_byte(x: usize, y: usize) -> usize {
    mem::size_of::<Lane>() * idx(x, y)
}

// Notes for read/write/xor_lane:
// These could be optimized by having state be u64 aligned so that we
// can directly store/load/xor lanes on LE architectures.
impl State {
    /// Retrieve the [`Lane`] with coordinates `x` and `y`.
    fn lane(&self, x: usize, y: usize) -> Lane {
        let start = lane_start_byte(x, y);
        // TODO check whether this optimizes to a simple unaligned load
        //  potentially optimize this by hand. The slice index is likely
        //  not optimized out
        let bytes = self.bytes[start..start + 8]
            .try_into()
            // TODO: Check optimization
            //  Very likely to be optimized out
            .expect("slice has length 8");
        Lane::from_le_bytes(bytes)
    }

    /// Overwrite the [`Lane`] at coordinates `x` and `y` with the provided
    /// [`Lane`].
    fn write_lane(&mut self, x: usize, y: usize, lane: Lane) {
        // TODO does this properly optimize on an LE architecture?
        let bytes = lane.to_le_bytes();
        let start = lane_start_byte(x, y);
        self.bytes[start..start + 8].copy_from_slice(&bytes);
    }

    /// In-place XOR of the [`Lane`] at coordinates `x` and `y` with the
    /// provided [`Lane`].
    fn xor_lane(&mut self, x: usize, y: usize, lane: Lane) {
        // TODO Unlikely that this properly optimizes on LE arches
        //  If the state where u64 aligned, this would be much more efficient
        let bytes = lane.to_le_bytes();
        let start = lane_start_byte(x, y);
        for (state_byte, byte) in self.bytes[start..start + 8].iter_mut().zip(bytes) {
            *state_byte ^= byte
        }
    }
}

/// 3.2.1 Algorithm 1: θ(A)
fn theta(A: &mut State) {
    // We have 5 * 64 columns, whose parity bits we can store in 5 lanes
    let mut C: [Lane; 5] = Default::default();
    // Step 1
    // Computes the parity of the columns
    for (x, Cx) in C.iter_mut().enumerate() {
        // One iteration computes the parity bits of one sheet
        *Cx ^= A.lane(x, 0);
        *Cx ^= A.lane(x, 1);
        *Cx ^= A.lane(x, 2);
        *Cx ^= A.lane(x, 3);
        *Cx ^= A.lane(x, 4);
    }

    // Interleaved step 2 and 3
    for x in 0..5 {
        // Step 2
        // Compute the θ effect for a given sheet (column x lane)
        // (x + 4) % 5 is equivalent to (x - 1) % 5 in the spec
        let D = C[(x + 4) % 5] ^ C[(x + 1) % 5].rotate_left(1);
        // Add the θ effect to the whole sheet
        for y in 0..5 {
            // Step 3
            A.xor_lane(x, y, D);
        }
    }
}

/// Table 2: Values are modulo the width w = 64
/// In row-major order starting with x = 0, y = 0
// TODO: Compute this table with a const function to be closer to spec?
const KECCAK_RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// 3.2.2 Algorithm 2: ρ(A)
///
/// Quote from 3.2.2 (description of ρ):
/// > The effect of ρ is to rotate the bits of each lane by a length, called the
/// > offset, which depends on the fixed x and y coordinates of the
/// > lane. Equivalently, for each bit in the lane, the z coordinate is
/// > modified by adding the offset, modulo the lane size.
fn rho(A: &mut State) {
    for x in 0..5 {
        for y in 0..5 {
            let rotated = A.lane(x, y).rotate_left(KECCAK_RHO_OFFSETS[x + 5 * y]);
            A.write_lane(x, y, rotated);
        }
    }
}

/// 3.2.3 Algorithm 3: π(A)
///
/// Quote from 3.2.3 (description of π):
/// > The effect of π is to rearrange the positions of the lanes, as illustrated
/// > for any slice in Figure 5 below.
fn pi(A: &mut State) {
    let temp_A = *A;
    for x in 0..5 {
        for y in 0..5 {
            // TODO: Why is the indexing in the ref implementation
            //  different than in the spec? It must be equivalent
            A.write_lane(y, 2 * x + 3 * y, temp_A.lane(x, y));
        }
    }
}

/// 3.2.3 Algorithm 4: χ(A)
///
/// Quote from 3.2.4:
/// > The effect of χ is to XOR each bit with a non-linear function of two other
/// > bits in its row
fn chi(A: &mut State) {
    let mut C: [Lane; 5] = Default::default();

    for y in 0..5 {
        for (x, Cx) in C.iter_mut().enumerate() {
            *Cx = A.lane(x, y) ^ (!A.lane(x + 1, y) & A.lane(x + 2, y));
        }
        for (x, Cx) in C.into_iter().enumerate() {
            A.write_lane(x, y, Cx);
        }
    }
}

/// Round-constants applied to the (0, 0) lane in the [`iota`] step.
/// Table taken from:
/// https://github.com/XKCP/XKCP/blob/716f007dd73ef28d357b8162173646be574ad1b7/lib/low/KeccakP-1600/ref-64bits/KeccakP-1600-reference.c#L109-L135
// TODO: Compute this table with a const function to be closer to spec?
const KECCAK_ROUND_CONSTANTS: [Lane; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// 3.2.5 Algorithm 6: ι(A, ir)
///
/// Quote from 3.2.5:
/// > The effect of ι is to modify some of the bits of Lane (0, 0) in a manner
/// > that depends on the round
/// > index ir. The other 24 lanes are not affected by ι.
fn iota(A: &mut State, round: usize) {
    A.xor_lane(0, 0, KECCAK_ROUND_CONSTANTS[round]);
}

/// 3.3 Algorithm 7: KECCAK-p[b, nr](S)
///
/// Not the generic algorithm, but specialized to `b = 1600` and `nr = 24`.
/// See Section 3.4 of FIPS 202.
fn keccakf_1600_state_permute(state: &mut State) {
    for round in 0..ROUNDS {
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, round);
    }
}

/// 4. and 5. Sponge Construction instantiated with `pad10*1` and
///    `KECCAK-p[1600, 24]`
// TODO split this function into init/absorbing/squeezing stages. This would
//  allow a lower level API  where data can be absorbed multiple times into the
//  state (`update`)
// TODO have domain separation suffix as parameter to reuse
//  keccak for SHAEK XOFs (currently hard-coded for SHA3)
// TODO Only have capacity as parameter and compute rate to be closer to spec?
pub(crate) fn keccak(rate: usize, capacity: usize, mut input: &[u8], mut output: &mut [u8]) {
    let mut state = State { bytes: [0_u8; 200] };
    let rate_in_bytes = rate / 8;
    let mut block_size = 0;

    assert_eq!(1600, rate + capacity);
    assert_eq!(0, rate % 8);

    let mut input_byte_len = input.len();

    // TODO: more idiomatic by iterating over input.chunks(rate_in_bytes)
    // Absorb input blocks
    while input_byte_len > 0 {
        block_size = cmp::min(input_byte_len, rate_in_bytes);
        for (state_i, input_i) in state.bytes[..block_size].iter_mut().zip(input) {
            *state_i ^= input_i;
        }
        input = &input[block_size..];
        input_byte_len -= block_size;

        if block_size == rate_in_bytes {
            keccakf_1600_state_permute(&mut state);
            block_size = 0;
        }
    }

    // Add domain separator and first 1 bit of padding
    state.bytes[block_size] ^= DELIMETED_SUFFIX;
    // Add second 1 bit of padding
    state.bytes[rate_in_bytes - 1] ^= 0b10000000_u8;

    // squeezing phase
    keccakf_1600_state_permute(&mut state);

    // TODO: more idiomatic by iterating over output.chunks(rate_in_bytes)
    let mut output_byte_len = output.len();
    while output_byte_len > 0 {
        let block_size = cmp::min(output_byte_len, rate_in_bytes);
        output.copy_from_slice(&state.bytes[..block_size]);
        output = &mut output[block_size..];
        output_byte_len -= block_size;

        if output_byte_len > 0 {
            keccakf_1600_state_permute(&mut state);
        }
    }
}
