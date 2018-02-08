use std::u8;
use util;
use std::cmp;

pub fn encrypt_repeating_xor(buf: &[u8], key: &[u8]) -> Vec<u8> {

    let repeat_key = key.iter().cloned().cycle();
    
    return buf.iter()
                .zip(repeat_key)
                .map(|(x, y)| x ^ y)
                .collect();
}

pub fn decrypt_single_byte_xor(encoded: &[u8]) -> Option<(u8, String, f64)> {
    let mut bufs_with_freqs = Vec::new();
    for c in 0..u8::MAX {
        let xored = util::xor_with_single(&encoded, c);
        let freq = score_for_buf(&xored);
        bufs_with_freqs.push((xored, c, freq));
    } 

    bufs_with_freqs.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap());

    for (buf, c, freq) in bufs_with_freqs {
        if let Ok(str) = String::from_utf8(buf) {
            return Some((c, str, freq));
        }
    }

    return None;
}

const LETTER_FREQS: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.2118182         // Y, Z, ' '
];

fn score_for_buf(buf: &[u8]) -> f64 {
    let mut counts = [0u64; 27];
    for b in buf {
        match *b {
            b'a' ... b'z' => counts[(*b - b'a') as usize] += 1,
            b'A' ... b'Z' => counts[(*b - b'A') as usize] += 1,
            b' ' => counts[26] += 1,
            _ => ()
        }
    }

    let mut score = 0.0;

    for i in 0..27 {
        let observed_prob = (counts[i] as f64) / (buf.len() as f64);
        score += (observed_prob * LETTER_FREQS[i]).sqrt();
    }
    return -score;
}

pub fn decrypt_repeating_xor(buf: &[u8]) -> Option<(String, Vec<u8>)> {

    let keysizes = guess_keysizes(buf, 10);
    let mut keys_with_scores = Vec::new();
    for keysize in keysizes {
        if let Some((key, score)) = try_keysize(buf, keysize) {
            keys_with_scores.push((key, score));
        }
    }

    let mut min_score = 1.0;
    let mut decrypted = None;
    for (key, _) in keys_with_scores {
        let xored_buf = encrypt_repeating_xor(buf, &key);
        let score = score_for_buf(&xored_buf);
        if score < min_score {
            if let Ok(str) = String::from_utf8(xored_buf) {
                decrypted = Some((str, key));
                min_score = score;
            }
        }
    }

    return decrypted;

}

fn try_keysize(buf: &[u8], keysize: usize) -> Option<(Vec<u8>, f64)> {
    let mut key = Vec::with_capacity(keysize);
    let mut key_score = 0.0;
    for offset in 0..keysize {
        let mut buf_offset = Vec::new();
        let mut pos = offset;
        while pos < buf.len() {
            buf_offset.push(buf[pos]);
            pos += keysize;
        }
        let single_decrypt = decrypt_single_byte_xor(&buf_offset);
        match single_decrypt {
            Some((key_byte, _, score)) => {
                key.push(key_byte);
                key_score += score;
            }
            _ => return None
        }
    }
    return Some((key, key_score));
}

const KEYSIZE_BLOCKS_TO_TRY: usize = 4;

fn get_avg_hamming_dist(blocks: Vec<&[u8]>) -> f64 {
    let mut norm_dists = Vec::new();
    for i in 0..(blocks.len() - 1) {
        for j in (i + 1)..blocks.len() {
            let norm_dist = util::hamming_distance(blocks[i], blocks[j]) as f64;
            println!("Norm dist: {}", norm_dist);
            norm_dists.push(norm_dist)
        }
    }

    let sum: f64 = norm_dists.iter().sum();
    return sum / (blocks[0].len() as f64);
}

fn guess_keysizes(buf: &[u8], keysizes_num: isize) -> Vec<usize> {
    let mut keysizes_with_dists = Vec::new();

    assert!(KEYSIZE_BLOCKS_TO_TRY > 1);
    for k in 2..40 {
        if KEYSIZE_BLOCKS_TO_TRY * k <= buf.len() {
            let mut blocks = Vec::new();
            for i in 0..KEYSIZE_BLOCKS_TO_TRY {
                blocks.push(&buf[(i * k)..(k * (i + 1))]);
            }
            keysizes_with_dists.push((k, get_avg_hamming_dist(blocks)));
        }
    }

    for &(k, d) in keysizes_with_dists.iter () {
        println!("Keysize: {}, score: {}", k, d);
    }
    
    keysizes_with_dists.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    return keysizes_with_dists.iter()
                                .cloned()
                                .take(cmp::min(keysizes_num as usize, keysizes_with_dists.len() as usize))
                                .map(|(k, _)| k)
                                .collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use util::*;

    #[test]
    fn encrypt_repeating_xor_works() {
        let to_encode = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        let encoded_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let key = "ICE".as_bytes();
        assert_eq!(hex_to_binary(encoded_hex).unwrap(), encrypt_repeating_xor(to_encode.as_bytes(), key));
    }

    #[test]
    fn decrypt_single_byte_xor_works() {
        let decrypted_expected = "Cooking MC's like a pound of bacon".to_string();
        let encoded = hex_to_binary("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        match decrypt_single_byte_xor(&encoded) {
            Some((_, decrypted, _)) => assert_eq!(decrypted_expected, decrypted),
            _ => assert!(false)
        }
    }

    #[test]
    fn decrypt_repeating_xor_works() {
        let to_encode = "Collaborate and listen
Ice is back with my brand new invention
Something grabs a hold of me tightly
Then I flow that a harpoon daily and nightly
Will it ever stop?
Yo, I don't know
Turn off the lights and I'll glow
To the extreme, I rock a mic like a vandal
Light up a stage and wax a chump like a candle";
        let key = "ICE t baby".as_bytes();
        let encoded = encrypt_repeating_xor(to_encode.as_bytes(), key);
        let (decoded, _) = decrypt_repeating_xor(&encoded).unwrap();
        assert_eq!(to_encode.to_string(), decoded);
    }

}