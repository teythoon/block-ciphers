//! CTR mode flavors

use cipher::{
    generic_array::{ArrayLength, GenericArray},
    Counter,
};

mod ctr128;
mod ctr32;
mod ctr64;

pub use ctr128::*;
pub use ctr32::*;
pub use ctr64::*;

/// Trait implemented by different counter types used in the CTR mode.
pub trait CtrFlavor<B>
where
    Self: Default + Clone,
    B: ArrayLength<u8>,
{
    /// Inner representation of nonce.
    type Nonce: Clone;
    /// Backend numeric type
    type Backend: Counter;

    /// Return number of remaining blocks.
    ///
    /// If result does not fit into `usize`, returns `None`.
    fn remaining(&self) -> Option<usize>;

    /// Generate block for given `nonce` and current counter value.
    fn generate_block(&self, nonce: &Self::Nonce) -> GenericArray<u8, B>;

    /// Increment counter.
    fn increment(&mut self);

    /// Load nonce from bytes.
    fn load_nonce(block: &GenericArray<u8, B>) -> Self::Nonce;

    /// Convert from a backend value
    fn from_backend(v: Self::Backend) -> Self;

    /// Convert to a backend value
    fn into_backend(&self) -> Self::Backend;
}
