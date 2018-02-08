use util;

const B64_TABLE: [u8; 64] = [b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', 
                            b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', 
                            b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', 
                            b'Y', b'Z', b'a', b'b', b'c', b'd', b'e', b'f', 
                            b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', 
                            b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', 
                            b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', 
                            b'4', b'5', b'6', b'7', b'8', b'9', b'+', b'/'];

pub fn b64_encode_bytes_hex_str(input: &str) -> Option<String> {
    if let Some(bytes) = util::hex_to_binary(input) {
        Some(b64_encode(&bytes))
    } else {
        None
    }
}

fn b64_encode_block(a: u8, b: u8, c: u8, padding: u8) -> [u8; 4] {
    let b1 = a >> 2;
    let b2 = ((a & 3u8) << 4) | (b >> 4);
    let b3 = ((b & 0xfu8) << 2) | (c >> 6);
    let b4 = (c << 2) >> 2;

    let mut res = [b'='; 4];
    res[0] = B64_TABLE[b1 as usize];
    res[1] = B64_TABLE[b2 as usize];
    if padding < 2 {
        res[2] = B64_TABLE[b3 as usize];
        if padding < 1 {
            res[3] = B64_TABLE[b4 as usize];
        }
    }
    return res;
}

pub fn b64_encode(input: &[u8]) -> String {
    let mut res = Vec::new();

    let mut offset_end = 3;
    while offset_end <= input.len() {
        let a = input[offset_end - 3];
        let b = input[offset_end - 2];
        let c = input[offset_end - 1];

        res.extend_from_slice(&b64_encode_block(a, b, c, 0));

        offset_end += 3;
    }

    if offset_end - input.len() == 1 {
        res.extend_from_slice(&b64_encode_block(input[input.len() - 2], input[input.len() - 1], 0, 1));
    }

    if offset_end - input.len() == 2 {
        res.extend_from_slice(&b64_encode_block(input[input.len() - 1], 0, 0, 2));
    }

    return String::from_utf8(res).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_encode_works() {
        assert_eq!("TWFu".to_string(), b64_encode(b"Man"));
        assert_eq!("TQ==".to_string(), b64_encode(b"M"));
        assert_eq!("TWE=".to_string(), b64_encode(b"Ma"));
        assert_eq!("YW55IGNhcm5hbCBwbGVhc3VyZS4=".to_string(), b64_encode(b"any carnal pleasure."));
    }

    #[test]
    fn b64_encode_hex_string_works() {
        assert_eq!(Some("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string()),
                    b64_encode_bytes_hex_str(
                        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));
    }
}