//! KECCAK Sponge construction with incremental API.
use std::marker::PhantomData;

use const_array::{Array, ArrayLen, AtMost, SameLen, Sum};

use crate::permute::{State, StateSize};

/// Parameters of a sponge over Keccakf[1600].
///
/// This trait is public, but can't be named outside of this crate. This
/// seals the public traits which have it as a supertrait. Implement it with
/// [`sponge_params!`].
pub trait SpongeParams: Clone {
    /// Number of bytes absorbed or squeezed per permutation.
    type Rate: ArrayLen;
    /// Number of bytes of the state which are not directly in- or output.
    type Capacity: ArrayLen;
    /// Proof that the state consists of the rate followed by the capacity.
    const STATE_SPLIT: SameLen<StateSize, Sum<Self::Rate, Self::Capacity>>;
    /// Domain separation suffix, followed by the first bit of the padding.
    const DELIMITED_SUFFIX: u8;
}

/// Implement [`SpongeParams`] for a marker type from the capacity in bits and
/// the domain separation suffix.
macro_rules! sponge_params {
    ($marker:ty, capacity_bits: $bits:expr, suffix: $suffix:expr $(,)?) => {
        impl $crate::sponge::SpongeParams for $marker {
            type Rate = ::const_array::Len<{ (1600 - $bits) / 8 }>;
            type Capacity = ::const_array::Len<{ $bits / 8 }>;
            const STATE_SPLIT: ::const_array::SameLen<
                $crate::permute::StateSize,
                ::const_array::Sum<Self::Rate, Self::Capacity>,
            > = ::const_array::same_len!(
                $crate::permute::StateSize,
                ::const_array::Sum<Self::Rate, Self::Capacity>
            );
            const DELIMITED_SUFFIX: u8 = $suffix;
        }
    };
}
pub(crate) use sponge_params;

impl State {
    fn rate<P: SpongeParams>(&self) -> &Array<u8, P::Rate> {
        self.bytes().cast_ref(P::STATE_SPLIT).split_ref().0
    }

    fn rate_mut<P: SpongeParams>(&mut self) -> &mut Array<u8, P::Rate> {
        self.bytes_mut().cast_mut(P::STATE_SPLIT).split_mut().0
    }
}

/// Absorb bytes into the Keccakf[1600] state.
#[derive(Clone)]
pub(crate) struct AbsorbState<P> {
    pos: usize,
    state: State,
    _params: PhantomData<P>,
}

impl<P: SpongeParams> AbsorbState<P> {
    pub(crate) fn new() -> Self {
        Self {
            pos: 0,
            state: State::new(),
            _params: PhantomData,
        }
    }

    pub(crate) fn absorb(&mut self, msg: &[u8]) {
        // first, we handle a potentially partial block, either due to and
        // advanced position or msg.len() < RATE
        let partial_block_len = (P::Rate::USIZE - self.pos).min(msg.len());
        let (first_msg, rest_msg) = msg.split_at(partial_block_len);
        xor_bytes(&mut self.state.rate_mut::<P>()[self.pos..], first_msg);
        // if the state was filled, we permute and reset the position
        if self.pos + partial_block_len == P::Rate::USIZE {
            self.state.keccakf_1600_permute();
            self.pos = 0;
        } else {
            // otherwise, we increment the position.
            self.pos += partial_block_len;
            // this branch is only taken if self.pos + partial_block_len < RATE,
            // so we know that rest_msg.is_empty() and can safely
            // return
            debug_assert!(rest_msg.is_empty());
            return;
        }

        // Absorb the remaining message
        let (blocks, rest) = Array::<u8, P::Rate>::slice_as_chunks(rest_msg);
        for block in blocks {
            self.state
                .rate_mut::<P>()
                .zip_mut_with(block, |state, input| *state ^= input);
            self.state.keccakf_1600_permute();
        }
        self.pos = rest.len();
        xor_bytes(self.state.rate_mut::<P>(), rest);
    }

    /// Add domain separator and padding and turn into [`SqueezeState`].
    ///
    /// Note that this performs no permute! Contrary to to FIPS202, we define
    /// the squeezing phase to start with a permutation (instead of ending
    /// the absorption with a permutation).
    pub(crate) fn into_squeeze(self) -> SqueezeState<P> {
        SqueezeState::new(self.pad())
    }

    /// Add domain separator and padding and squeeze an output which fits into
    /// a single block.
    ///
    /// This is equivalent to, but cheaper than, squeezing `O::USIZE` bytes
    /// from [`AbsorbState::into_squeeze`].
    pub(crate) fn squeeze_block<O: ArrayLen>(self, fits: AtMost<O, P::Rate>) -> Array<u8, O> {
        let mut state = self.pad();
        state.keccakf_1600_permute();
        state.rate::<P>().prefix_ref(fits).clone()
    }

    fn pad(mut self) -> State {
        let rate = self.state.rate_mut::<P>();
        rate[self.pos] ^= P::DELIMITED_SUFFIX;
        rate[P::Rate::USIZE - 1] ^= 0b10000000_u8;
        self.state
    }
}

/// Squeeze bytes from the Keccakf[1600] state.
#[derive(Clone)]
pub(crate) struct SqueezeState<P> {
    pos: usize,
    state: State,
    _params: PhantomData<P>,
}

impl<P: SpongeParams> SqueezeState<P> {
    fn new(state: State) -> Self {
        Self {
            pos: 0,
            state,
            _params: PhantomData,
        }
    }

    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }

        if self.pos == 0 {
            self.state.keccakf_1600_permute();
        }
        let partial_block_len = (P::Rate::USIZE - self.pos).min(output.len());
        let (first_output, rest_output) = output.split_at_mut(partial_block_len);
        first_output.copy_from_slice(&self.state.rate::<P>()[self.pos..][..partial_block_len]);
        self.pos = (self.pos + partial_block_len) % P::Rate::USIZE;
        if rest_output.is_empty() {
            return;
        }

        // The first block was used up, so every following block starts with
        // a permutation.
        let (blocks, rest) = Array::<u8, P::Rate>::slice_as_chunks_mut(rest_output);
        for block in blocks {
            self.state.keccakf_1600_permute();
            block.clone_from(self.state.rate::<P>());
        }
        if !rest.is_empty() {
            self.state.keccakf_1600_permute();
            self.pos = rest.len();
            rest.copy_from_slice(&self.state.rate::<P>()[..self.pos]);
        }
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
    use const_array::ArrayLen;

    use crate::{
        hasher::Out256,
        sponge::{AbsorbState, SpongeParams},
        xof::Security128,
    };

    #[test]
    fn partial_absorb() {
        const RATE_SHA_256: usize = <Out256 as SpongeParams>::Rate::USIZE;
        let sizes: Vec<Vec<usize>> = vec![
            vec![0],
            vec![0, 0],
            vec![0, 30],
            vec![0, 30, 200],
            vec![30, 200],
            vec![RATE_SHA_256, 200],
            vec![40, RATE_SHA_256 - 40],
            vec![40, RATE_SHA_256 - 40, 30],
            vec![40, RATE_SHA_256 - 40, 30, 0, 20],
            vec![15, 20, 40, RATE_SHA_256 - 15 - 20 - 40, 20],
        ];
        for msg_sizes in sizes {
            let mut absorb = AbsorbState::<Out256>::new();
            let msgs: Vec<_> = msg_sizes.iter().map(|size| vec![0; *size]).collect();
            let complete_msg = vec![0; msg_sizes.iter().sum()];
            for msg in &msgs {
                absorb.absorb(msg);
            }
            let mut squeeze = absorb.into_squeeze();
            let mut output = [0; 32];
            squeeze.squeeze(&mut output);
            let expected = libcrux_sha3::sha256(&complete_msg);
            assert_eq!(
                expected, output,
                "{msg_sizes:?}, msgs: {msgs:?} complete: {complete_msg:?}"
            );
        }
    }

    #[test]
    fn partial_squeeze() {
        const RATE_SHAKE_128: usize = <Security128 as SpongeParams>::Rate::USIZE;
        let sizes: Vec<Vec<usize>> = vec![
            vec![0],
            vec![0, 0],
            vec![0, 30],
            vec![0, 30, 200],
            vec![30, 200],
            vec![30, 2 * RATE_SHAKE_128 + 10],
            vec![RATE_SHAKE_128, 200],
            vec![40, RATE_SHAKE_128 - 40],
            vec![40, RATE_SHAKE_128 - 40, 30],
            vec![40, RATE_SHAKE_128 - 40, 30, 0, 20],
            vec![15, 20, 40, RATE_SHAKE_128 - 15 - 20 - 40, 20],
        ];
        let input = [42; 42];
        for out_sizes in sizes {
            let mut absorb = AbsorbState::<Security128>::new();
            absorb.absorb(&input);
            let mut squeeze = absorb.into_squeeze();
            let total_len = out_sizes.iter().sum();
            let mut output = vec![0; total_len];
            let mut start = 0;
            for &out_size in &out_sizes {
                squeeze.squeeze(&mut output[start..][..out_size]);
                start += out_size;
            }
            let mut expected = vec![0; total_len];
            libcrux_sha3::shake128_ema(&mut expected, &input);
            assert_eq!(expected, output, "{out_sizes:?}");
        }
    }
}
