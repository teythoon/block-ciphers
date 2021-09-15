#![feature(test)]

cipher::stream_cipher_sync_bench!(ctr::Ctr64LE<aes::Aes128>);
