//! [Cipher Block Chaining][1] (CBC) mode.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{ArrayLength, GenericArray},
    inout::{InOut, InOutBuf, InSrc, InTmpOutBuf},
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState,
};

/// CBC mode encryptor.
#[derive(Clone)]
pub struct Encrypt<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockSizeUser for Encrypt<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Encrypt<C> {
    fn encrypt_block_inout_mut(&mut self, mut block: InOut<'_, Block<Self>>) {
        let mut t = block.get_in().clone();
        xor(&mut t, &self.iv);
        self.cipher
            .encrypt_block_b2b_mut(&t, block.reborrow().get_out());
        self.iv = block.get_out().clone();
    }
}

impl<C: BlockEncryptMut + BlockCipher> InnerUser for Encrypt<C> {
    type Inner = C;
}

impl<C: BlockEncryptMut + BlockCipher> IvSizeUser for Encrypt<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Encrypt<C> {
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Encrypt<C> {
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

/// CBC mode decryptor.
#[derive(Clone)]
pub struct Decrypt<C: BlockDecryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockDecryptMut + BlockCipher> BlockSizeUser for Decrypt<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockDecryptMut + BlockCipher> BlockDecryptMut for Decrypt<C> {
    fn decrypt_block_inout_mut(&mut self, mut block: InOut<'_, Block<Self>>) {
        let enc_block = block.get_in().clone();
        self.cipher
            .decrypt_block_b2b_mut(&enc_block, block.reborrow().get_out());
        xor(block.get_out(), &self.iv);
        self.iv = enc_block;
    }

    fn decrypt_blocks_with_pre_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        mut post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        let iv = &mut self.iv;
        self.cipher
            .decrypt_blocks_with_pre_mut(blocks, pre_fn, |mut buf| {
                let n = buf.len();
                let (in_buf, tmp_buf) = buf.reborrow().get_in_tmp();
                xor(&mut tmp_buf[0], iv);
                for i in 1..n {
                    xor(&mut tmp_buf[i], &in_buf[i - 1])
                }
                *iv = in_buf[n - 1].clone();
                post_fn(buf);
            });
    }
}

impl<C: BlockDecryptMut + BlockCipher> InnerUser for Decrypt<C> {
    type Inner = C;
}

impl<C: BlockDecryptMut + BlockCipher> IvSizeUser for Decrypt<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockDecryptMut + BlockCipher> InnerIvInit for Decrypt<C> {
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockDecryptMut + BlockCipher> IvState for Decrypt<C> {
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(out: &mut GenericArray<u8, N>, buf: &GenericArray<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
