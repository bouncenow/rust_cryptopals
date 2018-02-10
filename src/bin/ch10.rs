extern crate base64;
extern crate rucry;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

use rucry::block;
use rucry::util;

const BLOCK_SIZE: usize = 16;

fn main() {
    let f = File::open("10.txt").expect("File not found");
    let f = BufReader::new(f);

    let mut to_decrypt = String::new();
    for line in f.lines() {
        to_decrypt.push_str(&line.unwrap());
    }

    let encrypted_bytes = base64::decode(&to_decrypt).unwrap();
    let key = b"YELLOW SUBMARINE";
    let iv = [0u8; BLOCK_SIZE];

    match block::aes_cbc_decrypt(key, &encrypted_bytes, &iv, block::Padding::NoPadding) {
        Some(bytes) => {
            match String::from_utf8(bytes.to_vec()) {
                Ok(str) => println!("Decrypted as:\n\"{}\"", str),
                Err(_) => println!("Decrypted as not valid string, hex value: {}", util::binary_to_hex(&bytes))
            }
        }
        _ => println!("Error during decryption")
    }
}