use std::fmt::Write;
use std::u8;

use rand::Rng;
use rand::os;

pub fn hex_to_binary(hex_str: &str) -> Option<Vec<u8>> {
    assert!(hex_str.len() % 2 == 0);
    let mut res: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < hex_str.len() {
        let hex_byte = &hex_str[i..(i + 2)];
        match u8::from_str_radix(hex_byte, 16) {
            Ok(byte) => res.push(byte),
            _ => return None
        }
        i += 2;
    }

    return Some(res);
}

pub fn binary_to_hex(buf: &[u8]) -> String {

    let mut res = String::with_capacity(buf.len() * 2);
    for b in buf {
        let a = b >> 4;
        let b = (b << 4) >> 4;
        write!(&mut res, "{:x}", a).unwrap();
        write!(&mut res, "{:x}", b).unwrap();
    }
    return res;
}

pub fn xor_bufs(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    assert_eq!(buf1.len(), buf2.len());
    
    return buf1.iter()
                .zip(buf2.iter())
                .map(|(x, y)| x ^ y)
                .collect();
}

pub fn xor_with_single(buf: &[u8], c: u8) -> Vec<u8> {
    return buf.iter()
                .map(|x| x ^ c)
                .collect();
}

pub fn xor_hex_bufs(hex_str1: &str, hex_str2: &str) -> Option<String> {

    if let Some(ref buf1) = hex_to_binary(hex_str1) {
        if let Some(ref buf2) = hex_to_binary(hex_str2) {
            if buf1.len() == buf2.len() {
                return Some(binary_to_hex(&xor_bufs(buf1, buf2)))
            }
        }
    }

    return None;
}

pub fn hamming_distance(buf1: &[u8], buf2: &[u8]) -> u32 {
    assert_eq!(buf1.len(), buf2.len());

    return buf1.iter()
                .zip(buf2.iter())
                .map(|(x, y)| (x ^ y).count_ones())
                .sum();
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut os_rng = os::OsRng::new().unwrap();

    let mut rand_buf = vec![0u8; len];
    os_rng.fill_bytes(&mut rand_buf);

    rand_buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_binary_works() {
        assert_eq!(Some(vec![2u8, 10u8, 12u8]), hex_to_binary("020A0C"));
        assert_eq!(Some(vec![13u8]), hex_to_binary("0D"));
        assert_eq!(Some(vec![]), hex_to_binary(""));
        assert_eq!(None, hex_to_binary("1232G3"));
    }

    #[test]
    fn xor_hex_bufs_works() {
        assert_eq!(Some("746865206b696420646f6e277420706c6179".to_string()),
                    xor_hex_bufs("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"));
    }

    #[test]
    fn hamming_distance_works() {
        let buf1 = "this is a test".as_bytes();
        let buf2 = "wokka wokka!!!".as_bytes();
        assert_eq!(37, hamming_distance(&buf1, &buf2));
    }
}