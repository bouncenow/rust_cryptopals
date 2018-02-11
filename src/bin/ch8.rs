extern crate base64;
extern crate rucry;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

use rucry::util;
use rucry::block;

const BLOCK_SIZE: usize = 16;

fn main() {
    let f = File::open("8.txt").expect("File not found");
    let f = BufReader::new(f);

    let mut cipher_texts_with_dists = Vec::new();
    for line in f.lines() {
        let hex_str = line.unwrap();
        let c_text_bytes = util::hex_to_binary(&hex_str).unwrap();
        assert!(c_text_bytes.len() % BLOCK_SIZE == 0);

        let hamming_dist = block::block_hamming_average_dist(&c_text_bytes, block::BLOCK_SIZE);
        cipher_texts_with_dists.push((c_text_bytes, hamming_dist));
    }

    cipher_texts_with_dists.sort_by(|x, y| x.1.partial_cmp(&y.1).unwrap());

    for &(_, hamming) in cipher_texts_with_dists.iter().take(5) {
        println!("Hamming dist: {}", hamming);
    }

    let &(ref buf, _) = &cipher_texts_with_dists[0];

    for i in 0..(buf.len() / BLOCK_SIZE) {
        println!("{:?}", &buf[(i * BLOCK_SIZE)..((i + 1) * BLOCK_SIZE)]);
    }
}