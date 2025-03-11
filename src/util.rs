use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};

use crate::u2ferror::U2fError;

/// The `Result` type used in this crate.
type Result<T> = ::std::result::Result<T, U2fError>;

pub const U2F_V2: &str = "U2F_V2";

// Generates a challenge from a secure, random source.
pub fn generate_challenge(size: usize) -> Result<Vec<u8>> {
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    let mut rng = StdRng::from_os_rng();

    let mut bytes: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut bytes);
    Ok(bytes)
}

pub fn expiration(timestamp: String) -> TimeDelta {
    let now: DateTime<Utc> = Utc::now();
    let ts = timestamp.parse::<DateTime<Utc>>();
    now.signed_duration_since(ts.unwrap())
}

// Decode initial bytes of buffer as ASN and return the length of the encoded structure.
// http://en.wikipedia.org/wiki/X.690
pub fn asn_length(mem: Bytes) -> Result<usize> {
    let buffer: &[u8] = &mem[..];

    if mem.len() < 2 || buffer[0] != 0x30 {
        // Type
        return Err(U2fError::Asm1DecoderError);
    }

    let len = buffer[1]; // Len
    if len & 0x80 == 0 {
        return Ok((len & 0x7f) as usize);
    }

    let numbem_of_bytes = len & 0x7f;
    if numbem_of_bytes == 0 {
        return Err(U2fError::Asm1DecoderError);
    }

    let mut length: usize = 0;
    for num in 0..numbem_of_bytes {
        length = length * 0x100 + (buffer[(2 + num) as usize] as usize);
    }

    length += numbem_of_bytes as usize;

    Ok(length + 2) // Add the 2 initial bytes: type and length.
}

pub fn get_encoded(data: &[u8]) -> String {
    let encoded: String = URL_SAFE_NO_PAD.encode(data);
    encoded.trim_end_matches('=').to_string()
}
