extern crate rand;
extern crate rucry;

use rucry::block;
use rucry::block::EncryptionMode;
use rucry::util;
use rand::{thread_rng, Rng};
use std::collections::HashMap;

const PLAINTEXT_SIZE: usize = 30;
const SIMULATIONS_NUMBER: usize = 1000;

fn main() {

    for block_len in vec![2, 4, 8, 16] {
        println!("Average hamming dist, block len {}:", block_len);
        descriptive_simulations(b"AAAAAAA", |data| block::block_hamming_average_dist(data, block_len), false);
        println!("\n");
        println!("Number of non unique blocks:");
        descriptive_simulations(b"AAAAAAA", |data| num_of_non_unique_blocks(data, block_len), false);
        println!("\n");
        println!("Number of non unique blocks (with offsets):");
        descriptive_simulations(b"AAAAAAA", |data| num_of_non_unique_blocks_with_offset(data, block_len), false);
        println!("\n");
    }
   
}

fn num_of_non_unique_blocks(data: &[u8], block_len: usize) -> f64 {
    let mut blocks_set = HashMap::new();

    for block in data.chunks(block_len) {
        let count = blocks_set.entry(block).or_insert(0);
        *count += 1;
    }

    let mut non_unique: f64 = 0.0;
    for (_, count) in &blocks_set {
        if *count > 1 {
            non_unique += 1.0;
        }
    }

    non_unique
}

const MAX_OFFSET: usize = 10;

fn num_of_non_unique_blocks_with_offset(data: &[u8], block_len: usize) -> f64 {
    let mut max = -1.0;

    for offset in 0..MAX_OFFSET {
        let non_unique = num_of_non_unique_blocks(&data[offset..], block_len);
        if non_unique > max {
            max = non_unique;
        }
    }

    max
}

fn descriptive_simulations<T: Fn(&[u8]) -> f64>(plaintext: &[u8], metric: T, verbose: bool) {
    let mut cbc_sum = 0.0;
    let mut cbc_count = 0;
    let mut ecb_sum = 0.0;
    let mut ecb_count = 0;
    for i in 0..SIMULATIONS_NUMBER {
        let (cipher_text, mode) = block::encryption_oracle(plaintext);
        let average_hamming_dist = metric(&cipher_text);
        if verbose {
            println!("Simulation {}: {:?}, metric: {}", i, mode, average_hamming_dist);
        }
        if mode == EncryptionMode::CBC {
            cbc_count += 1;
            cbc_sum += average_hamming_dist;
        } else {
            ecb_count += 1;
            ecb_sum += average_hamming_dist;
        }
    }

    println!("Average ECB metric: {}", ecb_sum / (ecb_count as f64));
    println!("Average CBC metric: {}", cbc_sum / (cbc_count as f64));

}

fn encryption_mode_by_hamming(cipher_text: &[u8], threshold: f64) -> EncryptionMode {
    let average_hamming_dist = block::block_hamming_average_dist(cipher_text, block::BLOCK_SIZE);
    if average_hamming_dist > threshold {
        EncryptionMode::CBC
    } else {
        EncryptionMode::ECB
    }
}

fn run_simulations<T: Fn(&[u8]) -> EncryptionMode>(sim_num: usize, oracle: T) -> f64 {
    let data = util::generate_random_bytes(PLAINTEXT_SIZE);
    let mut guessed = 0;
    for i in 0..sim_num {
        let (cipher_text, mode) = block::encryption_oracle(&data);
        let guessed_mode = oracle(&cipher_text);
        if guessed_mode == mode {
            guessed += 1;
        }
    }

    (guessed as f64) / (sim_num as f64)
}