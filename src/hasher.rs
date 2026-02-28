use crate::sponge::{Absorb, AbsorbState, Squeeze};

pub struct Hasher<S: HashSize> {
    state: S::State,
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
            state: S::State::init(),
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.state.absorb(msg);
    }

    pub fn finalize(self) -> S::Output {
        let mut output = S::Output::default();
        let mut squeeze = self.state.into_squeeze::<0b110>();
        squeeze.squeeze(output.as_mut());
        output
    }
}

impl<S: HashSize> Default for Hasher<S> {
    fn default() -> Self {
        Self {
            state: S::State::init(),
        }
    }
}

#[allow(private_bounds)]
pub trait HashSize: Params {
    type Output: Output;
}

trait Params {
    type State: Absorb;
}

impl HashSize for Out224 {
    type Output = [u8; 28];
}

impl Params for Out224 {
    type State = AbsorbState<{ (1600 - 224 * 2) / 8 }>;
}

impl HashSize for Out256 {
    type Output = [u8; 32];
}

impl Params for Out256 {
    type State = AbsorbState<{ (1600 - 256 * 2) / 8 }>;
}

impl HashSize for Out384 {
    type Output = [u8; 48];
}

impl Params for Out384 {
    type State = AbsorbState<{ (1600 - 384 * 2) / 8 }>;
}

impl HashSize for Out512 {
    type Output = [u8; 64];
}

impl Params for Out512 {
    type State = AbsorbState<{ (1600 - 512 * 2) / 8 }>;
}

// The normal Default trait is not implemented for arrays with len > 32, so we
// define this helper trait
pub trait Output: AsMut<[u8]> + private::Sealed {
    fn default() -> Self;
}

impl<const N: usize> Output for [u8; N] {
    fn default() -> Self {
        [0; N]
    }
}

mod private {
    impl<const N: usize> Sealed for [u8; N] {}

    pub trait Sealed {}
}
