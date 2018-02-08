extern crate rucry;
extern crate base64;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

use rucry::xor;

fn main() {
    let f = File::open("6.txt").expect("File not found");
    let f = BufReader::new(f);

    let mut to_decrypt = String::new();
    for line in f.lines() {
        to_decrypt.push_str(&line.unwrap());
    }

    let encrypted_bytes = base64::decode(&to_decrypt).unwrap();
    if let Some((text, key)) = xor::decrypt_repeating_xor(&encrypted_bytes) {
        println!("Decrypted as:\n\"{}\"\n, with key=\"{:?}\"", text, key);
    }
}