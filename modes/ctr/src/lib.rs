//! Generic implementations of CTR mode for block ciphers.
//!
//! Mode functionality is accessed using traits from re-exported
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! # ⚠️ Security Warning: [Hazmat!]
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # `Ctr128` Usage Example
//!
//! ```
//! use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
//!
//! // `aes` crate provides AES block cipher implementation
//! type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//!
//! let key = b"very secret key.";
//! let nonce = b"and secret nonce";
//!
//! // create cipher instance
//! let mut cipher = Aes128Ctr::new(key.into(), nonce.into());
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream_inplace(&mut data);
//! assert_eq!(data, [6, 245, 126, 124, 180, 146, 37]);
//!
//! // seek to the keystream beginning and apply it again to the `data` (decrypt)
//! cipher.seek(0);
//! cipher.apply_keystream_inplace(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! ```
//!
//! [Hazmat!]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/ctr/0.8.0"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;
use cipher::{
    crypto_common::{InnerUser, IvUser},
    inout::{InOutBuf, InSrc},
    Block, BlockEncryptMut, BlockUser, InnerIvInit, Iv, IvState, StreamCipherCore,
    StreamCipherCoreWrapper, StreamCipherSeekCore,
};

pub mod flavors;
use flavors::CtrFlavor;

// TODO: wrap into streaming wrapper

/// CTR mode with 128-bit big endian counter.
pub type Ctr128BE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr128BE>>;
/// CTR mode with 128-bit little endian counter.
pub type Ctr128LE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr128LE>>;
/// CTR mode with 64-bit big endian counter.
pub type Ctr64BE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr64BE>>;
/// CTR mode with 64-bit little endian counter.
pub type Ctr64LE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr64LE>>;
/// CTR mode with 32-bit big endian counter.
pub type Ctr32BE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr32BE>>;
/// CTR mode with 32-bit little endian counter.
pub type Ctr32LE<B> = StreamCipherCoreWrapper<CtrCore<B, flavors::Ctr32LE>>;

/// Generic CTR block mode isntance.
#[derive(Clone)]
pub struct CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    cipher: B,
    nonce: <F as CtrFlavor<B::BlockSize>>::Nonce,
    counter: F,
}

impl<B, F> BlockUser for CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    type BlockSize = B::BlockSize;
}

impl<B, F> StreamCipherCore for CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    fn remaining_blocks(&self) -> Option<usize> {
        self.counter.remaining()
    }

    fn apply_keystream_blocks(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        mut pre_fn: impl FnMut(&[Block<Self>]),
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        let Self {
            cipher,
            nonce,
            counter,
        } = self;
        cipher.encrypt_blocks_with_pre_mut(
            blocks,
            |mut buf| {
                pre_fn(buf.reborrow().get_in());
                for block in buf.get_tmp() {
                    *block = counter.generate_block(nonce);
                    counter.increment();
                }
                InSrc::Tmp
            },
            |mut buf| {
                buf.xor_intmp2out();
                post_fn(buf.get_out());
            },
        )
    }
}

impl<B, F> StreamCipherSeekCore for CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    type Counter = F::Backend;

    fn get_block_pos(&self) -> Self::Counter {
        self.counter.into_backend()
    }

    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.counter = F::from_backend(pos);
    }
}

impl<B, F> InnerUser for CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    type Inner = B;
}

impl<B, F> IvUser for CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    type IvSize = B::BlockSize;
}

impl<B, F> InnerIvInit for CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    #[inline]
    fn inner_iv_init(cipher: B, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            nonce: F::load_nonce(iv),
            counter: Default::default(),
        }
    }
}

impl<B, F> IvState for CtrCore<B, F>
where
    B: BlockEncryptMut,
    F: CtrFlavor<B::BlockSize>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.counter.generate_block(&self.nonce)
    }
}
