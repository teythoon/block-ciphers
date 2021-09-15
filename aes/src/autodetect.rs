//! Autodetection support for hardware accelerated AES backends with fallback
//! to the fixsliced "soft" implementation.

use core::fmt;
use crate::{soft, Block};
use cipher::{
    consts::{U16, U24, U32},
    generic_array::GenericArray,
    inout::{InOutBuf, InOut, InTmpOutBuf, InSrc},
    BlockCipher, BlockSizeUser, BlockDecrypt, BlockEncrypt, KeySizeUser, KeyInit,
};
use core::mem::ManuallyDrop;

#[cfg(all(target_arch = "aarch64", feature = "armv8"))]
use crate::armv8 as intrinsics;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::ni as intrinsics;

cpufeatures::new!(aes_intrinsics, "aes");

macro_rules! define_aes_impl {
    (
        $name:tt,
        $module:tt,
        $key_size:ty,
        $doc:expr
    ) => {
        #[doc=$doc]
        pub struct $name {
            inner: $module::Inner,
            token: aes_intrinsics::InitToken,
        }

        mod $module {
            use super::{intrinsics, soft};
            use core::mem::ManuallyDrop;

            pub(super) union Inner {
                pub(super) intrinsics: ManuallyDrop<intrinsics::$name>,
                pub(super) soft: ManuallyDrop<soft::$name>,
            }
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let (token, aesni_present) = aes_intrinsics::init_get();

                let inner = if aesni_present {
                    $module::Inner {
                        intrinsics: ManuallyDrop::new(intrinsics::$name::new(key)),
                    }
                } else {
                    $module::Inner {
                        soft: ManuallyDrop::new(soft::$name::new(key)),
                    }
                };

                Self { inner, token }
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                let inner = if self.token.get() {
                    $module::Inner {
                        intrinsics: unsafe { self.inner.intrinsics.clone() },
                    }
                } else {
                    $module::Inner {
                        soft: unsafe { self.inner.soft.clone() },
                    }
                };

                Self {
                    inner,
                    token: self.token,
                }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl BlockCipher for $name {}

        impl BlockEncrypt for $name {
            #[inline]
            fn encrypt_block_inout(&self, block: InOut<'_, Block>) {
                if self.token.get() {
                    unsafe { self.inner.intrinsics.encrypt_block_inout(block) }
                } else {
                    unsafe { self.inner.soft.encrypt_block_inout(block) }
                }
            }

            #[inline]
            fn encrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                if self.token.get() {
                    unsafe { self.inner.intrinsics.encrypt_blocks_with_pre(blocks, pre_fn, post_fn) }
                } else {
                    unsafe { self.inner.soft.encrypt_blocks_with_pre(blocks, pre_fn, post_fn) }
                }
            }
        }

        impl BlockDecrypt for $name {
            #[inline]
            fn decrypt_block_inout(&self, block: InOut<'_, Block>) {
                if self.token.get() {
                    unsafe { self.inner.intrinsics.decrypt_block_inout(block) }
                } else {
                    unsafe { self.inner.soft.decrypt_block_inout(block) }
                }
            }

            #[inline]
            fn decrypt_blocks_with_pre(
                &self,
                blocks: InOutBuf<'_, Block>,
                pre_fn: impl FnMut(InTmpOutBuf<'_, Block>) -> InSrc,
                post_fn: impl FnMut(InTmpOutBuf<'_, Block>),
            ) {
                if self.token.get() {
                    unsafe { self.inner.intrinsics.decrypt_blocks_with_pre(blocks, pre_fn, post_fn) }
                } else {
                    unsafe { self.inner.soft.decrypt_blocks_with_pre(blocks, pre_fn, post_fn) }
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

define_aes_impl!(Aes128, aes128, U16, "AES-128 block cipher instance");
define_aes_impl!(Aes192, aes192, U24, "AES-192 block cipher instance");
define_aes_impl!(Aes256, aes256, U32, "AES-256 block cipher instance");

#[cfg(all(feature = "ctr", target_arch = "aarch64"))]
pub(crate) mod ctr {
    use super::{Aes128, Aes192, Aes256};

    /// AES-128 in CTR mode
    pub type Aes128Ctr = ::ctr::Ctr64BE<Aes128>;

    /// AES-192 in CTR mode
    pub type Aes192Ctr = ::ctr::Ctr64BE<Aes192>;

    /// AES-256 in CTR mode
    pub type Aes256Ctr = ::ctr::Ctr64BE<Aes256>;
}

#[cfg(all(feature = "ctr", any(target_arch = "x86_64", target_arch = "x86")))]
pub(crate) mod ctr {
    use super::{Aes128, Aes192, Aes256};
    use crate::{ni, soft};
    use cipher::{
        errors::{LoopError, OverflowError},
        generic_array::GenericArray,
        BlockCipher, FromBlockCipher, SeekNum, StreamCipher, StreamCipherSeek,
    };
    use core::mem::ManuallyDrop;

    cpufeatures::new!(aes_ssse3_cpuid, "aes", "ssse3");

    macro_rules! define_aes_ctr_impl {
        (
            $name:tt,
            $cipher:ident,
            $module:tt,
            $doc:expr
        ) => {
            #[doc=$doc]
            #[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
            pub struct $name {
                inner: $module::Inner,
                token: aes_ssse3_cpuid::InitToken,
            }

            mod $module {
                use crate::{ni, soft};
                use core::mem::ManuallyDrop;

                pub(super) union Inner {
                    pub(super) ni: ManuallyDrop<ni::$name>,
                    pub(super) soft: ManuallyDrop<soft::$name>,
                }
            }

            impl FromBlockCipher for $name {
                type BlockCipher = $cipher;
                type NonceSize = <$cipher as BlockCipher>::BlockSize;

                fn from_block_cipher(
                    cipher: $cipher,
                    nonce: &GenericArray<u8, Self::NonceSize>,
                ) -> Self {
                    let (token, aesni_present) = aes_ssse3_cpuid::init_get();

                    let inner = if aesni_present {
                        let ni = ni::$name::from_block_cipher(
                            unsafe { (*cipher.inner.intrinsics).clone() },
                            nonce,
                        );

                        $module::Inner {
                            ni: ManuallyDrop::new(ni),
                        }
                    } else {
                        let soft = soft::$name::from_block_cipher(
                            unsafe { (*cipher.inner.soft).clone() },
                            nonce,
                        );

                        $module::Inner {
                            soft: ManuallyDrop::new(soft),
                        }
                    };

                    Self { inner, token }
                }
            }

            impl StreamCipher for $name {
                #[inline]
                fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
                    if self.token.get() {
                        unsafe { (*self.inner.ni).try_apply_keystream(data) }
                    } else {
                        unsafe { (*self.inner.soft).try_apply_keystream(data) }
                    }
                }
            }

            impl StreamCipherSeek for $name {
                #[inline]
                fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
                    if self.token.get() {
                        unsafe { (*self.inner.ni).try_current_pos() }
                    } else {
                        unsafe { (*self.inner.soft).try_current_pos() }
                    }
                }

                #[inline]
                fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), LoopError> {
                    if self.token.get() {
                        unsafe { (*self.inner.ni).try_seek(pos) }
                    } else {
                        unsafe { (*self.inner.soft).try_seek(pos) }
                    }
                }
            }

            opaque_debug::implement!($name);
        };
    }

    define_aes_ctr_impl!(Aes128Ctr, Aes128, aes128ctr, "AES-128 in CTR mode");
    define_aes_ctr_impl!(Aes192Ctr, Aes192, aes192ctr, "AES-192 in CTR mode");
    define_aes_ctr_impl!(Aes256Ctr, Aes256, aes256ctr, "AES-256 in CTR mode");
}
