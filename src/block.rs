use std::u8;

use openssl::symm;
use openssl::error::ErrorStack;
use rand::{thread_rng, Rng};

use util;

pub enum Padding {
    NoPadding,
    PKCS7,
}

#[derive(PartialEq, Debug)]
pub enum EncryptionMode {
    ECB,
    CBC,
}

pub const BLOCK_SIZE: usize = 16;

fn aes_decrypt_block(
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    assert_eq!(BLOCK_SIZE, data.len());
    let mut c = symm::Crypter::new(
        symm::Cipher::aes_128_ecb(),
        symm::Mode::Decrypt,
        key,
        None).unwrap();
    c.pad(false);
    let mut out = vec![0; BLOCK_SIZE + data.len()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

fn aes_encrypt_block(
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    assert_eq!(BLOCK_SIZE, data.len());
    let mut c = symm::Crypter::new(
        symm::Cipher::aes_128_ecb(),
        symm::Mode::Encrypt,
        key,
        None).unwrap();
    c.pad(false);
    let mut out = vec![0; BLOCK_SIZE + data.len()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

pub fn aes_ecb_decrypt(key: &[u8], data: &[u8], padding: Padding) -> Option<Vec<u8>> {

    assert!(data.len() % BLOCK_SIZE == 0);
    let blocks = data.len() / BLOCK_SIZE;

    let mut decrypted = Vec::new();

    for i in 0..blocks {
        let block_start = i * BLOCK_SIZE;
        let block_end = block_start + BLOCK_SIZE;
        let ct_block = &data[block_start..block_end];
        match aes_decrypt_block(key, ct_block) {
            Ok(pt_block) => decrypted.extend_from_slice(&pt_block),
            _ => return None
        }
    }

    match padding {
        Padding::NoPadding => Some(decrypted),
        Padding::PKCS7 => unpad_pkcs(decrypted)
    }
}

pub fn aes_ecb_encrypt(key: &[u8], data: &[u8], padding: Padding) -> Option<Vec<u8>> {
    let bytes_padded;
    let data = match padding {
        Padding::NoPadding => {
            assert!(data.len() % BLOCK_SIZE == 0);
            data
        },
        Padding::PKCS7 => {
            let clone = data.to_vec();
            bytes_padded = pad_pkcs(clone, BLOCK_SIZE);
            &bytes_padded
        }
    };

    let mut encrypted = Vec::new();
    let blocks = data.len() / BLOCK_SIZE;

    for i in 0..blocks {
        let block_start = i * BLOCK_SIZE;
        let block_end = block_start + BLOCK_SIZE;
        let plaintext_block = &data[block_start..block_end];

        match aes_encrypt_block(key, plaintext_block) {
            Ok(ct_block) => encrypted.extend_from_slice(&ct_block),
            _ => return None
        }
    }

    Some(encrypted)
}

pub fn aes_cbc_encrypt(key: &[u8], data: &[u8], iv: &[u8], padding: Padding) -> Option<Vec<u8>> {
    let bytes_padded;
    let data = match padding {
        Padding::NoPadding => {
            assert!(data.len() % BLOCK_SIZE == 0);
            data
        },
        Padding::PKCS7 => {
            let clone = data.to_vec();
            bytes_padded = pad_pkcs(clone, BLOCK_SIZE);
            &bytes_padded
        }
    };

    let blocks = data.len() / BLOCK_SIZE;
    let mut encrypted = Vec::with_capacity(data.len());
    let mut previous_block = iv.to_vec();

    for i in 0..blocks {
        let block_start = i * BLOCK_SIZE;
        let block_end = block_start + BLOCK_SIZE;
        let plaintext_block = &data[block_start..block_end];
        let xored = util::xor_bufs(plaintext_block, &previous_block);
        match aes_encrypt_block(key, &xored) {
            Ok(ct_block) => {
                encrypted.extend_from_slice(&ct_block);
                previous_block = ct_block.to_vec();
            }
            _ => return None
        }
    }
    
    Some(encrypted)
}

pub fn aes_cbc_decrypt(key: &[u8], data: &[u8], iv: &[u8], padding: Padding) -> Option<Vec<u8>> {
    assert!(data.len() % BLOCK_SIZE == 0);
    let blocks = data.len() / BLOCK_SIZE;

    let mut decrypted = Vec::with_capacity(data.len());
    
    let mut previous_block = iv;
    for i in 0..blocks {
        let block_start = i * BLOCK_SIZE;
        let block_end = block_start + BLOCK_SIZE;
        let encrypted_block = &data[block_start..block_end];

        let decrypted_block_raw = match aes_decrypt_block(key, &encrypted_block) {
            Ok(pt_block) => pt_block,
            Err(err) => {
                println!("Error during decryption of block {}: {:?}", i, err);
                return None;
            }
        };
        let decrypted_block = util::xor_bufs(&decrypted_block_raw, previous_block);
        decrypted.extend_from_slice(&decrypted_block);
        previous_block = encrypted_block;
    }

    match padding {
        Padding::NoPadding => Some(decrypted),
        Padding::PKCS7 => unpad_pkcs(decrypted)
    }
}

pub fn pad_pkcs(mut buf: Vec<u8>, block_size: usize) -> Vec<u8> {
    let desired_block_size = if block_size > buf.len() {
        block_size
    } else if block_size == buf.len() {
        block_size + block_size
    } else {
        block_size * (1 + buf.len() / block_size)
    };
    let bytes_to_pad = desired_block_size - buf.len();
    assert!(bytes_to_pad < (u8::MAX as usize));
    
    for _ in 0..bytes_to_pad {
        buf.push(bytes_to_pad as u8);
    }

    buf
}

fn unpad_pkcs(mut buf: Vec<u8>) -> Option<Vec<u8>> {

    if buf.len() <= BLOCK_SIZE {
        return None;
    }

    let padding_byte = buf[buf.len() - 1];
    if padding_byte >= (BLOCK_SIZE as u8) {
        return None;
    }

    for i in 0..(padding_byte as usize) {
        if buf[buf.len() - 1 - i] != padding_byte {
            return None;
        }
    }

    let prev_len = buf.len();
    buf.truncate(prev_len - (padding_byte as usize));
    Some(buf)
}

const MIN_RANDOM_PADDING: usize = 5;
const MAX_RANDOM_PADDING: usize = 10;

fn generate_random_mode() -> EncryptionMode {
    let i = thread_rng().gen_range(0, 2);
    if i == 0 {
        EncryptionMode::CBC
    } else {
        EncryptionMode::ECB
    }
}

pub fn encryption_oracle(data: &[u8]) -> (Vec<u8>, EncryptionMode) {

    let mut padded = Vec::new();
    let pad_before = thread_rng().gen_range(MIN_RANDOM_PADDING, MAX_RANDOM_PADDING);
    let pad_after = thread_rng().gen_range(MIN_RANDOM_PADDING, MAX_RANDOM_PADDING);
    padded.extend_from_slice(&util::generate_random_bytes(pad_before));
    padded.extend_from_slice(data);
    padded.extend_from_slice(&util::generate_random_bytes(pad_after));

    let key = util::generate_random_bytes(BLOCK_SIZE);

    match generate_random_mode() {
        EncryptionMode::ECB => (aes_ecb_encrypt(&key, &padded, Padding::PKCS7).unwrap(), EncryptionMode::ECB),
        EncryptionMode::CBC => {
            let iv = util::generate_random_bytes(BLOCK_SIZE);
            (aes_cbc_encrypt(&key, &padded, &iv, Padding::PKCS7).unwrap(), EncryptionMode::CBC)
        }
    }
}

pub fn block_hamming_average_dist(buf: &[u8], block_len: usize) -> f64 {

    let mut dists: Vec<u32> = Vec::new();

    let block_num = buf.len() / block_len;
    for i in 0..(block_num - 1) {
        for j in (i + 1)..block_num {
            let block1 = &buf[(i * block_len)..((i + 1) * block_len)];
            let block2 = &buf[(j * block_len)..((j + 1) * block_len)];
            dists.push(util::hamming_distance(block1, block2));
        }
    }

    return (dists.iter().sum::<u32>() as f64) / (dists.len() as f64);
}

pub fn decryption_oracle(cipher_text: &[u8]) -> EncryptionMode {
    EncryptionMode::CBC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_pkcs_works() {
        let buf_to_pad = b"YELLOW SUBMARINE".to_vec();
        let expected_with_pad = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();
        assert_eq!(expected_with_pad, pad_pkcs(buf_to_pad, 20));

        let buf_to_pad = b"YELLOW SUBMARINE".to_vec();
        let expected_with_pad = b"YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08".to_vec();
        assert_eq!(expected_with_pad, pad_pkcs(buf_to_pad, 8));
    }

    #[test]
    fn aes_ecb_encrypt_works() {
        let to_encrypt = b"YELLOW SUBMARINE".to_vec();
        println!("len of to encrypt: {}", to_encrypt.len());
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let encrypted = aes_ecb_encrypt(key, &to_encrypt, Padding::NoPadding).unwrap();
        println!("Encrypted: {:?}, with len = {}", encrypted, encrypted.len());
        let decrypted = aes_ecb_decrypt(key, &encrypted, Padding::NoPadding).unwrap();
        assert_eq!(to_encrypt, decrypted);
    }

    #[test]
    fn aes_cbc_works() {
        let to_encrypt = b"YELLOW SUBMARINE, this string is longer and probably should be padded".to_vec();
        println!("len of to encrypt: {}", to_encrypt.len());
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let iv = b"\x00\x01\x01\x04\x07\x02\x06\x07\x08\x0B\x0A\x0B\x0C\x0D\x0E\x0F";
        let encrypted = aes_cbc_encrypt(key, &to_encrypt, iv, Padding::PKCS7).unwrap();
        println!("Encrypted: {:?}, with len = {}", encrypted, encrypted.len());
        let decrypted = aes_cbc_decrypt(key, &encrypted, iv, Padding::PKCS7).unwrap();
        assert_eq!(to_encrypt, decrypted);
    }
}