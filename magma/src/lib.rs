//! Implementation of the [block cipher][1] defined in GOST 28147-89
//! and GOST R 34.12-2015.
//!
//! # Examples
//! ```
//! use magma::Magma;
//! use magma::cipher::{
//!     generic_array::GenericArray,
//!     BlockEncrypt, BlockDecrypt, KeyInit,
//! };
//! use hex_literal::hex;
//!
//! // Example vector from GOST 34.12-2018
//! let key = hex!("
//!     FFEEDDCCBBAA99887766554433221100
//!     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
//! ");
//! let plaintext = hex!("FEDCBA9876543210");
//! let ciphertext = hex!("4EE901E5C2D8CA3D");
//!
//! let cipher = Magma::new(GenericArray::from_slice(&key));
//!
//! let mut block = GenericArray::clone_from_slice(&plaintext);
//! cipher.encrypt_block(&mut block);
//! assert_eq!(&ciphertext, block.as_slice());
//!
//! cipher.decrypt_block(&mut block);
//! assert_eq!(&plaintext, block.as_slice());
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/GOST_(block_cipher)
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub use cipher;

use cipher::{
    consts::{U32, U8},
    generic_array::GenericArray,
    inout::InOut,
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
};
use core::{convert::TryInto, marker::PhantomData};

mod sboxes;

pub use sboxes::Sbox;

/// Block over which the Kuznyechik cipher operates.
pub type Block = GenericArray<u8, U8>;
/// The Kuznyechik cipher initialization key.
pub type Key = GenericArray<u8, U32>;

/// Block cipher defined in GOST 28147-89 generic over S-box
#[derive(Clone, Copy)]
pub struct Gost89<S: Sbox> {
    key: [u32; 8],
    _p: PhantomData<S>,
}

impl<S: Sbox> KeySizeUser for Gost89<S> {
    type KeySize = U32;
}

impl<S: Sbox> KeyInit for Gost89<S> {
    fn new(key: &Key) -> Self {
        let mut key_u32 = [0u32; 8];
        key.chunks_exact(4)
            .zip(key_u32.iter_mut())
            .for_each(|(chunk, v)| *v = to_u32(chunk));
        Self {
            key: key_u32,
            _p: PhantomData,
        }
    }
}

impl<S: Sbox> BlockSizeUser for Gost89<S> {
    type BlockSize = U8;
}

impl<S: Sbox> BlockCipher for Gost89<S> {}

impl<S: Sbox> BlockEncrypt for Gost89<S> {
    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, Block>) {
        let b = block.get_in();
        let mut v = (to_u32(&b[0..4]), to_u32(&b[4..8]));
        for _ in 0..3 {
            for i in 0..8 {
                v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
            }
        }
        for i in (0..8).rev() {
            v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
        }
        let block = block.get_out();
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }
}

impl<S: Sbox> BlockDecrypt for Gost89<S> {
    #[inline]
    fn decrypt_block_inout(&self, block: InOut<'_, Block>) {
        let b = block.get_in();
        let mut v = (to_u32(&b[0..4]), to_u32(&b[4..8]));

        for i in 0..8 {
            v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
        }

        for _ in 0..3 {
            for i in (0..8).rev() {
                v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
            }
        }
        let block = block.get_out();
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }
}

/// Block cipher defined in GOST R 34.12-2015 (Magma)
pub type Magma = Gost89<sboxes::Tc26>;
/// Block cipher defined in GOST 28147-89 with test S-box
pub type Gost89Test = Gost89<sboxes::TestSbox>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version A
pub type Gost89CryptoProA = Gost89<sboxes::CryptoProA>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version B
pub type Gost89CryptoProB = Gost89<sboxes::CryptoProB>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version C
pub type Gost89CryptoProC = Gost89<sboxes::CryptoProC>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version D
pub type Gost89CryptoProD = Gost89<sboxes::CryptoProD>;

fn to_u32(chunk: &[u8]) -> u32 {
    u32::from_be_bytes(chunk.try_into().unwrap())
}
