extern crate openssl;
extern crate base64;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

use openssl::symm::{decrypt, Cipher};

fn main() {
    let f = File::open("7.txt").expect("File not found");
    let f = BufReader::new(f);

    let mut to_decrypt = String::new();
    for line in f.lines() {
        to_decrypt.push_str(&line.unwrap());
    }

    let encrypted_bytes = base64::decode(&to_decrypt).unwrap();

    let key = b"YELLOW SUBMARINE";

    let cipher = Cipher::aes_128_ecb();
    let decrypted = decrypt(cipher, key, None, &encrypted_bytes);
    match decrypted {
        Ok(bytes) => println!("Decrypted as:\n\"{}\"", String::from_utf8(bytes).unwrap()),
        Err(err) => println!("Error: {:?}", err)
    }
}