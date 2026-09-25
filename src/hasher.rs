use const_array::{Array, ArrayLen, AtMost, Len, SameLen, Sum, at_most, same_len};

use crate::{
    permute::StateSize,
    sponge::{AbsorbState, SpongeParams},
};

/// Domain separation suffix of the SHA-3 hash functions, followed by the
/// first bit of the padding.
const SHA3_SUFFIX: u8 = 0b110;

pub struct Hasher<S: HashSize> {
    state: AbsorbState<S>,
}

/// Marker type for 224-bit output.
pub struct Out224;
/// Marker type for 256-bit output.
pub struct Out256;
/// Marker type for 384-bit output.
pub struct Out384;
/// Marker type for 512-bit output.
pub struct Out512;

/// SHA-3 [`Hasher`] with 224-bit output.
pub type Sha3_224 = Hasher<Out224>;
/// SHA-3 [`Hasher`] with 256-bit output.
pub type Sha3_256 = Hasher<Out256>;
/// SHA-3 [`Hasher`] with 384-bit output.
pub type Sha3_384 = Hasher<Out384>;
/// SHA-3 [`Hasher`] with 512-bit output.
pub type Sha3_512 = Hasher<Out512>;

impl<S: HashSize> Hasher<S> {
    pub fn new() -> Self {
        Hasher {
            state: AbsorbState::new(),
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.state.absorb(msg);
    }

    pub fn finalize(self) -> Array<u8, S::OutputSize> {
        self.state
            .squeeze_block::<SHA3_SUFFIX, _>(S::OUTPUT_FITS_RATE)
    }
}

impl<S: HashSize> Default for Hasher<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Output size of a SHA-3 [`Hasher`].
///
/// This trait is sealed and implemented by [`Out224`], [`Out256`],
/// [`Out384`] and [`Out512`].
pub trait HashSize: SpongeParams {
    /// Size of the digest in bytes.
    type OutputSize: ArrayLen;
    /// Proof that the digest fits into a single block of the sponge, so it
    /// can be squeezed with a single permutation.
    const OUTPUT_FITS_RATE: AtMost<Self::OutputSize, Self::Rate>;
}

macro_rules! impl_hash_size {
    ($marker:ty, $bits:literal) => {
        impl SpongeParams for $marker {
            type Rate = Len<{ (1600 - $bits * 2) / 8 }>;
            type Capacity = Len<{ $bits * 2 / 8 }>;
            const STATE_SPLIT: SameLen<StateSize, Sum<Self::Rate, Self::Capacity>> =
                same_len!(StateSize, Sum<Self::Rate, Self::Capacity>);
        }

        impl HashSize for $marker {
            type OutputSize = Len<{ $bits / 8 }>;
            const OUTPUT_FITS_RATE: AtMost<Self::OutputSize, Self::Rate> =
                at_most!(Self::OutputSize, Self::Rate);
        }
    };
}

impl_hash_size!(Out224, 224);
impl_hash_size!(Out256, 256);
impl_hash_size!(Out384, 384);
impl_hash_size!(Out512, 512);
