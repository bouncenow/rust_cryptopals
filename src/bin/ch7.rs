extern crate base64;
extern crate rucry;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

use rucry::block;

fn main() {
    let f = File::open("7.txt").expect("File not found");
    let f = BufReader::new(f);

    let mut to_decrypt = String::new();
    for line in f.lines() {
        to_decrypt.push_str(&line.unwrap());
    }

    let encrypted_bytes = base64::decode(&to_decrypt).unwrap();

    let key = b"YELLOW SUBMARINE";

    match block::aes_ecb_decrypt(key, &encrypted_bytes, block::Padding::NoPadding) {
        Some(bytes) => println!("Decrypted as:\n\"{}\"", String::from_utf8(bytes).unwrap()),
        _ => println!("Error during decryption")
    }
}