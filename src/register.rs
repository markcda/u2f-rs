use bytes::{Bytes, BufMut};
use base64::{encode};
use ring::{error, signature};
use untrusted::Input;
use byteorder::{ByteOrder, BigEndian};
use crypto_hash::{Algorithm, hex_digest};

use webpki::trust_anchor_util;

use util::*;
use messages::RegisteredKey;
use u2ferror::U2fError;

/// The `Result` type used in this crate.
type Result<T> = ::std::result::Result<T, U2fError>;

// Single enrolment or pairing between an application and a token.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub key_handle: Vec<u8>,
    pub pub_key: Vec<u8>,

    // AttestationCert can be null for Authenticate requests.
    pub attestation_cert: Option<Vec<u8>>,
}

pub fn parse_registration(app_id: String, client_data: Vec<u8>, registration_data: Vec<u8>) -> Result<Registration> {
    let reserved_byte = registration_data[0];
    if reserved_byte != 0x05 {
        return Err(U2fError::InvalidReservedByte);
    }

    let mut mem = Bytes::from(registration_data);
    
    //Start parsing ... advance the reserved byte.
    let _ = mem.split_to(1);

    // P-256 NIST elliptic curve
    let public_key = mem.split_to(65);

    // Key Handle
    let key_handle_size = mem.split_to(1);
    let key_len = BigEndian::read_uint(&key_handle_size[..], 1);
    let key_handle = mem.split_to(key_len as usize);

    // The certificate length needs to be inferred by parsing.
    let cert_len = asn_length(mem.clone()).unwrap();
    let attestation_certificate = mem.split_to(cert_len);

    // Check certificate as trust anchor
    let anchor = trust_anchor_util::cert_der_as_trust_anchor(
        Input::from(&attestation_certificate[..])).unwrap();
  
    // Remaining data corresponds to the signature 
    let signature = mem;

    let app_id_hash = hex_digest(Algorithm::SHA256, &app_id.into_bytes());
    let client_data_hash = hex_digest(Algorithm::SHA256, &client_data[..]);

    let mut sig_base = vec![0x00]; // A byte reserved for future use [1 byte] with the value 0x00
    sig_base.put(app_id_hash);
    sig_base.put(client_data_hash);
    sig_base.put(key_handle.clone()); 
    sig_base.put(public_key.clone()); 

    let input_pub_key = Input::from(&anchor.spki[..]);
    let input_sig = Input::from(&signature[..]);
    let input_sig_base = Input::from(&sig_base[..]);

    // The signature is to be verified by the relying party using the public key certified
    // in the attestation certificate.
    signature::verify(&signature::ECDSA_P256_SHA256_ASN1, input_pub_key, input_sig_base, input_sig)
        .map_err(|error::Unspecified| U2fError::BadSignature)?;

    let registration = Registration {
        key_handle: key_handle[..].to_vec(),
        pub_key: public_key[..].to_vec(), 
        attestation_cert: Some(attestation_certificate[..].to_vec()),
    };

    Ok(registration)
}

pub fn get_registered_key(app_id: String, key_handle: Vec<u8>) -> RegisteredKey {
    RegisteredKey {
        app_id: app_id,
        version: U2F_V2.into(),
        key_handle: Some(encode(&key_handle[..]))
    }
}