//! [Infinite Garble Extension][1] (IGE) block cipher mode of operation.
//!
//! [1]: https://www.links.org/files/openssl-ige.pdf

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{
        sequence::Concat,
        typenum::{Sum, Unsigned},
        ArrayLength, GenericArray,
    },
    inout::InOut,
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState,
};
use core::ops::Add;

type BlockSize<C> = <C as BlockSizeUser>::BlockSize;
type IgeIvSize<C> = Sum<BlockSize<C>, BlockSize<C>>;

/// IGE mode encryptor.
#[derive(Clone)]
pub struct Encrypt<C>
where
    C: BlockEncryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    cipher: C,
    x: Block<C>,
    y: Block<C>,
}

impl<C> BlockEncryptMut for Encrypt<C>
where
    C: BlockEncryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        let new_x = block.get_in().clone();
        let mut t = block.get_in().clone();
        xor(&mut t, &self.y);
        self.cipher.encrypt_block_mut(&mut t);
        xor(&mut t, &self.x);
        *block.get_out() = t.clone();
        self.x = new_x;
        self.y = t;
    }
}

impl<C> BlockSizeUser for Encrypt<C>
where
    C: BlockEncryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for Encrypt<C>
where
    C: BlockEncryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    type Inner = C;
}

impl<C> IvSizeUser for Encrypt<C>
where
    C: BlockEncryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    type IvSize = IgeIvSize<C>;
}

impl<C> InnerIvInit for Encrypt<C>
where
    C: BlockEncryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let (y, x) = iv.split_at(C::BlockSize::to_usize());
        Self {
            cipher,
            x: GenericArray::clone_from_slice(x),
            y: GenericArray::clone_from_slice(y),
        }
    }
}

impl<C> IvState for Encrypt<C>
where
    C: BlockEncryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.y.clone().concat(self.x.clone())
    }
}

/// IGE mode decryptor.
#[derive(Clone)]
pub struct Decrypt<C>
where
    C: BlockDecryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    cipher: C,
    x: Block<C>,
    y: Block<C>,
}

impl<C> BlockDecryptMut for Decrypt<C>
where
    C: BlockDecryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        let new_y = block.get_in().clone();
        let mut t = block.get_in().clone();
        xor(&mut t, &self.x);
        self.cipher.decrypt_block_mut(&mut t);
        xor(&mut t, &self.y);
        *block.get_out() = t.clone();
        self.y = new_y;
        self.x = t;
    }
}

impl<C> BlockSizeUser for Decrypt<C>
where
    C: BlockDecryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for Decrypt<C>
where
    C: BlockDecryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decrypt<C>
where
    C: BlockDecryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    type IvSize = IgeIvSize<C>;
}

impl<C> InnerIvInit for Decrypt<C>
where
    C: BlockDecryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let (y, x) = iv.split_at(C::BlockSize::to_usize());
        Self {
            cipher,
            x: GenericArray::clone_from_slice(x),
            y: GenericArray::clone_from_slice(y),
        }
    }
}

impl<C> IvState for Decrypt<C>
where
    C: BlockDecryptMut + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArrayLength<u8>,
{
    fn iv_state(&self) -> Iv<Self> {
        self.y.clone().concat(self.x.clone())
    }
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(out: &mut GenericArray<u8, N>, buf: &GenericArray<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
