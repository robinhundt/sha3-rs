//! KECCAK permutation based on [XKCP]
//!
//! This implementation of KECCAK is based on the [readable and compact]
//! and the [ref-64-bits] implementations of the KECCAK Team. It is currently
//! written in slightly unidiomatic rust to closely adhere to the linked
//! reference implementation.
//!
//! [readable and compact]: https://github.com/XKCP/XKCP/blob/716f007dd73ef28d357b8162173646be574ad1b7/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
//! [ref-64-bits]: https://github.com/XKCP/XKCP/tree/716f007dd73ef28d357b8162173646be574ad1b7/lib/low/KeccakP-1600/ref-64bits
//! [XKCP]: https://github.com/XKCP/XKCP
#![allow(non_snake_case)]
use std::{
    mem,
    ops::{Index, IndexMut},
};

// NOTE: References to Sections, Algorithms, Tables, etc. refer to the
// FIPS 202 standard (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
// if not otherwise specified.

/// Number of rounds performed in `KECCAK-C`.
const ROUNDS: usize = 24;

/// Lane of the [`State`] array containing w = 64 bits.
type Lane = u64;

/// State array A of Keccakf[1600]. Contains 1600 bits.
#[derive(Clone, Copy)]
pub(crate) struct State<const RATE: usize>([Lane; 25]);

/// Compute a [`Lane`] index in [`State`].
#[inline(always)]
fn idx(x: usize, y: usize) -> usize {
    // % ops are optimized out
    (x % 5) + 5 * (y % 5)
}

impl<const RATE: usize> Index<(usize, usize)> for State<RATE> {
    type Output = Lane;

    #[inline(always)]
    fn index(&self, (x, y): (usize, usize)) -> &Self::Output {
        &self.0[idx(x, y)]
    }
}

impl<const RATE: usize> IndexMut<(usize, usize)> for State<RATE> {
    #[inline(always)]
    fn index_mut(&mut self, (x, y): (usize, usize)) -> &mut Self::Output {
        &mut self.0[idx(x, y)]
    }
}

impl<const RATE: usize> State<RATE> {
    pub(crate) fn new() -> Self {
        assert!(
            RATE == 144 || RATE == 136 || RATE == 104 || RATE == 72,
            "Invalid RATE for Keccakf[1600]"
        );

        Self([0; 25])
    }

    pub(crate) fn bytes(&self) -> &[u8; RATE] {
        assert!(RATE < mem::size_of::<[Lane; 25]>());
        // SAFETY:
        // - ptr is non-null
        // - ptr is correctly aligned (align(u8) < align(u64))
        // - pointed to memory is valid and correct size
        unsafe { &*self.0.as_ptr().cast() }
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; RATE] {
        assert!(RATE < mem::size_of::<[Lane; 25]>());
        // SAFETY:
        // - ptr is non-null
        // - ptr is correctly aligned (align(u8) < align(u64))
        // - pointed to memory is valid and correct size
        unsafe { &mut *self.0.as_mut_ptr().cast() }
    }

    /// 3.3 Algorithm 7: KECCAK-p[b, nr](S)
    ///
    /// Not the generic algorithm, but specialized to `b = 1600` and `nr = 24`.
    /// See Section 3.4 of FIPS 202.
    pub(crate) fn keccakf_1600_permute(&mut self) {
        self.lanes_to_le();
        for round in 0..ROUNDS {
            theta(self);
            rho(self);
            pi(self);
            chi(self);
            iota(self, round);
        }
        self.lanes_to_le();
    }

    /// On big-endian arch, convert lanes to little-endian by swapping bytes.
    ///
    /// No-op on little endian architecture.
    fn lanes_to_le(&mut self) {
        #[cfg(target_endian = "big")]
        self.0.iter_mut().for_each(|l| *l = l.to_le());
    }
}

/// 3.2.1 Algorithm 1: θ(A)
fn theta<const RATE: usize>(A: &mut State<RATE>) {
    // We have 5 * 64 columns, whose parity bits we can store in 5 lanes
    let mut C: [Lane; 5] = Default::default();
    // Step 1
    // Computes the parity of the columns
    for (x, Cx) in C.iter_mut().enumerate() {
        // One iteration computes the parity bits of one sheet
        *Cx ^= A[(x, 0)];
        *Cx ^= A[(x, 1)];
        *Cx ^= A[(x, 2)];
        *Cx ^= A[(x, 3)];
        *Cx ^= A[(x, 4)];
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
            A[(x, y)] ^= D;
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
fn rho<const RATE: usize>(A: &mut State<RATE>) {
    for x in 0..5 {
        for y in 0..5 {
            A[(x, y)] = A[(x, y)].rotate_left(KECCAK_RHO_OFFSETS[x + 5 * y]);
        }
    }
}

/// 3.2.3 Algorithm 3: π(A)
///
/// Quote from 3.2.3 (description of π):
/// > The effect of π is to rearrange the positions of the lanes, as illustrated
/// > for any slice in Figure 5 below.
fn pi<const RATE: usize>(A: &mut State<RATE>) {
    let temp_A = *A;
    for x in 0..5 {
        for y in 0..5 {
            // TODO: Why is the indexing in the ref implementation
            //  different than in the spec? It must be equivalent
            A[(y, 2 * x + 3 * y)] = temp_A[(x, y)];
        }
    }
}

/// 3.2.3 Algorithm 4: χ(A)
///
/// Quote from 3.2.4:
/// > The effect of χ is to XOR each bit with a non-linear function of two other
/// > bits in its row
fn chi<const RATE: usize>(A: &mut State<RATE>) {
    let mut C: [Lane; 5] = Default::default();

    for y in 0..5 {
        for (x, Cx) in C.iter_mut().enumerate() {
            *Cx = A[(x, y)] ^ (!A[(x + 1, y)] & A[(x + 2, y)]);
        }
        for (x, Cx) in C.into_iter().enumerate() {
            A[(x, y)] = Cx;
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
fn iota<const RATE: usize>(A: &mut State<RATE>, round: usize) {
    A[(0, 0)] ^= KECCAK_ROUND_CONSTANTS[round];
}
