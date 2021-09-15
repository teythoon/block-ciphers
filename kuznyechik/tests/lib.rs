#![cfg_attr(rustfmt, rustfmt_skip)]

use cipher::{generic_array::GenericArray, BlockEncrypt, BlockDecrypt, KeyInit};
use hex_literal::hex;
use kuznyechik::{Kuznyechik, Block};

/// Example vectors from GOST 34.12-2018
#[test]
fn kuznyechik() {
    let key = hex!("
        8899AABBCCDDEEFF0011223344556677
        FEDCBA98765432100123456789ABCDEF
    ");
    let plaintext = hex!("1122334455667700FFEEDDCCBBAA9988");
    let ciphertext = hex!("7F679D90BEBC24305a468d42b9d4EDCD");

    let cipher = Kuznyechik::new_from_slice(&key).unwrap();

    let mut block = GenericArray::clone_from_slice(&plaintext);
    cipher.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());

    // test that encrypt_blocks/decrypt_blocks work correctly
    let mut blocks = [Block::default(); 101];
    for (i, block) in blocks.iter_mut().enumerate() {
        block.iter_mut().enumerate().for_each(|(j, b)| {
            *b = (i + j) as u8;
        });
    }

    let mut blocks2 = blocks.clone();
    let blocks_cpy = blocks.clone();

    cipher.encrypt_blocks(&mut blocks, |_| {});
    assert!(blocks[..] != blocks_cpy[..]);
    for block in blocks2.iter_mut() {
        cipher.encrypt_block(block);
    }
    assert_eq!(blocks[..], blocks2[..]);

    cipher.decrypt_blocks(&mut blocks, |_| {});
    assert_eq!(blocks[..], blocks_cpy[..]);
    for block in blocks2.iter_mut().rev() {
        cipher.decrypt_block(block);
    }
    assert_eq!(blocks2[..], blocks_cpy[..]);
}
