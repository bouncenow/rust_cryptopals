extern crate rucry;

use rucry::util;
use rucry::xor;

fn main() {
    let encoded = util::hex_to_binary("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let (key, decoded, freq) = xor::decrypt_single_byte_xor(&encoded).unwrap();

    println!("Decoded as \"{}\" with key {} with character frequency {}", decoded, key, freq);
}