//! [Cipher feedback][1] (CFB) mode with full block feedback.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    inout::{InOut, InOutBuf, InSrc, InTmpOutBuf},
    AsyncStreamCipherCore, Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser,
    InnerIvInit, Iv, IvState, StreamCipherCoreWrapper,
};

/// Wrapped CFB which handles block buffering and provides slice-based
/// `encrypt` and `decrypt` methods.
pub type Cfb<C> = StreamCipherCoreWrapper<CfbCore<C>>;

/// CFB mode core type.
#[derive(Clone)]
pub struct CfbCore<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for CfbCore<C> {
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.cipher.encrypt_block_mut(&mut self.iv);
        xor(&mut self.iv, block.get_in());
        *block.get_out() = self.iv.clone();
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockDecryptMut for CfbCore<C> {
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        let mut t = Default::default();
        self.cipher.encrypt_block_b2b_mut(&self.iv, &mut t);
        xor(&mut t, block.get_in());
        self.iv = block.get_in().clone();
        *block.get_out() = t;
    }

    fn decrypt_blocks_with_pre_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        mut post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        let mut enc_iv = Default::default();
        self.cipher.encrypt_block_b2b_mut(&self.iv, &mut enc_iv);
        let iv = &mut self.iv;
        self.cipher
            .encrypt_blocks_with_pre_mut(blocks, pre_fn, |mut buf| {
                let len = buf.len();
                let (in_buf, tmp_buf) = buf.reborrow().get_in_tmp();
                for i in 0..len {
                    xor(&mut enc_iv, &in_buf[i]);
                    core::mem::swap(&mut tmp_buf[i], &mut enc_iv);
                }
                *iv = in_buf[len - 1].clone();
                post_fn(buf);
            });
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockSizeUser for CfbCore<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> AsyncStreamCipherCore for CfbCore<C> {}

impl<C: BlockEncryptMut + BlockCipher> InnerUser for CfbCore<C> {
    type Inner = C;
}

impl<C: BlockEncryptMut + BlockCipher> IvSizeUser for CfbCore<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for CfbCore<C> {
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for CfbCore<C> {
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

#[inline(always)]
fn xor(out: &mut [u8], buf: &[u8]) {
    assert_eq!(out.len(), buf.len());
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
