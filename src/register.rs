use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

use crate::messages::RegisteredKey;
use crate::u2ferror::U2fError;
use crate::util::*;

/// The `Result` type used in this crate.
type Result<T> = ::std::result::Result<T, U2fError>;

// Single enrolment or pairing between an application and a token.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub key_handle: Vec<u8>,
    pub pub_key: Vec<u8>,

    // AttestationCert can be null for Authenticate requests.
    pub attestation_cert: Option<Vec<u8>>,
    pub device_name: Option<String>,
}

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn parse_registration(
    app_id: String,
    client_data: Vec<u8>,
    registration_data: Vec<u8>,
) -> Result<Registration> {
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

    // Remaining data corresponds to the signature
    let signature = mem;

    // Let's build the msg to verify the signature
    let app_id_hash = sha256(&app_id.into_bytes());
    let client_data_hash = sha256(&client_data[..]);

    let mut msg = vec![0x00]; // A byte reserved for future use [1 byte] with the value 0x00
    msg.extend_from_slice(app_id_hash.as_ref());
    msg.extend_from_slice(client_data_hash.as_ref());
    msg.extend_from_slice(key_handle.as_ref());
    msg.extend_from_slice(public_key.as_ref());

    // The signature is to be verified by the relying party using the public key certified
    // in the attestation certificate.
    let cerificate_public_key =
        super::crypto::X509PublicKey::try_from(&attestation_certificate[..])?;

    if !(cerificate_public_key.is_secp256r1()?) {
        return Err(U2fError::BadCertificate);
    }

    cerificate_public_key.verify_signature(&signature[..], &msg[..])?;

    let registration = Registration {
        key_handle: key_handle[..].to_vec(),
        pub_key: public_key[..].to_vec(),
        attestation_cert: Some(attestation_certificate[..].to_vec()),
        device_name: cerificate_public_key.common_name(),
    };

    Ok(registration)
}

pub fn get_registered_key(app_id: String, key_handle: Vec<u8>) -> RegisteredKey {
    RegisteredKey {
        app_id,
        version: U2F_V2.into(),
        key_handle: Some(get_encoded(key_handle.as_slice())),
    }
}
