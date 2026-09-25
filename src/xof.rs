//! SHAKE extendable-output functions (XOFs).
use const_array::{Array, ArrayLen};

use crate::sponge::{AbsorbState, SpongeParams, SqueezeState, sponge_params};

/// Domain separation suffix of the SHAKE functions, followed by the first bit
/// of the padding.
const SHAKE_SUFFIX: u8 = 0b11111;

/// Absorbs the input of a SHAKE XOF.
///
/// Call [`Xof::finalize`] to obtain an [`XofReader`] for the output.
#[derive(Clone)]
pub struct Xof<S: XofSecurity> {
    state: AbsorbState<S>,
}

/// Squeezes an arbitrary amount of output from a SHAKE XOF.
#[derive(Clone)]
pub struct XofReader<S: XofSecurity> {
    state: SqueezeState<S>,
}

/// Marker type for 128-bit security.
#[derive(Clone, Copy, Debug)]
pub struct Security128;
/// Marker type for 256-bit security.
#[derive(Clone, Copy, Debug)]
pub struct Security256;

/// SHAKE128 [`Xof`].
pub type Shake128 = Xof<Security128>;
/// SHAKE256 [`Xof`].
pub type Shake256 = Xof<Security256>;
/// [`XofReader`] of [`Shake128`].
pub type Shake128Reader = XofReader<Security128>;
/// [`XofReader`] of [`Shake256`].
pub type Shake256Reader = XofReader<Security256>;

impl<S: XofSecurity> Xof<S> {
    pub fn new() -> Self {
        Xof {
            state: AbsorbState::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state.absorb(data);
    }

    pub fn finalize(self) -> XofReader<S> {
        XofReader {
            state: self.state.into_squeeze(),
        }
    }
}

impl<S: XofSecurity> Default for Xof<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: XofSecurity> XofReader<S> {
    /// Fill `output` with the next `output.len()` bytes.
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output);
    }

    /// Return the next `N::USIZE` bytes as an [`Array`].
    ///
    /// ```
    /// # use sha3::{Shake128, const_array::{Array, Len}};
    /// let mut xof = Shake128::new();
    /// xof.update(b"seed");
    /// let mut reader = xof.finalize();
    /// let key: Array<u8, Len<32>> = reader.squeeze_array();
    /// let nonce: Array<u8, Len<12>> = reader.squeeze_array();
    /// # let _ = (key, nonce);
    /// ```
    pub fn squeeze_array<N: ArrayLen>(&mut self) -> Array<u8, N> {
        let mut output = Array::default();
        self.squeeze(&mut output);
        output
    }
}

/// Security level of a SHAKE [`Xof`].
///
/// This trait is sealed and implemented by [`Security128`] and
/// [`Security256`].
pub trait XofSecurity: SpongeParams {}

sponge_params!(Security128, capacity_bits: 2 * 128, suffix: SHAKE_SUFFIX);
impl XofSecurity for Security128 {}

sponge_params!(Security256, capacity_bits: 2 * 256, suffix: SHAKE_SUFFIX);
impl XofSecurity for Security256 {}
