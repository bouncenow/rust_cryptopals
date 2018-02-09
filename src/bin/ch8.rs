extern crate base64;
extern crate rucry;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

use rucry::util;

const BLOCK_SIZE: usize = 16;

fn main() {
    let f = File::open("8.txt").expect("File not found");
    let f = BufReader::new(f);

    let mut cipher_texts_with_dists = Vec::new();
    for line in f.lines() {
        let hex_str = line.unwrap();
        let c_text_bytes = util::hex_to_binary(&hex_str).unwrap();
        assert!(c_text_bytes.len() % BLOCK_SIZE == 0);

        let hamming_dist = hamming_avg_dist(&c_text_bytes);
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

fn hamming_avg_dist(buf: &[u8]) -> f64 {

    let mut dists: Vec<u32> = Vec::new();

    let block_num = buf.len() / BLOCK_SIZE;
    for i in 0..(block_num - 1) {
        for j in (i + 1)..block_num {
            let block1 = &buf[(i * BLOCK_SIZE)..((i + 1) * BLOCK_SIZE)];
            let block2 = &buf[(j * BLOCK_SIZE)..((j + 1) * BLOCK_SIZE)];
            dists.push(util::hamming_distance(block1, block2));
        }
    }

    return (dists.iter().sum::<u32>() as f64) / (dists.len() as f64);
}