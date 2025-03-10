//! Cryptographic operation wrapper for Webauthn. This module exists to
//! allow ease of auditing, safe operation wrappers for the webauthn library,
//! and cryptographic provider abstraction. This module currently uses OpenSSL
//! as the cryptographic primitive provider.

// Source can be found here: https://github.com/Firstyear/webauthn-rs/blob/master/src/crypto.rs
// This module is rewritten not to use OpenSSL.

#![allow(non_camel_case_types)]

use ring::{digest, signature};
use std::convert::TryFrom;

use crate::u2ferror::U2fError;

/// An X509PublicKey. This is what is otherwise known as a public certificate
/// which comprises a public key and other signed metadata related to the issuer
/// of the key.
pub struct X509PublicKey<'a> {
    #[allow(dead_code)] cert: webpki::EndEntityCert<'a>,
    cert_der: &'a [u8],
}

impl std::fmt::Debug for X509PublicKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "X509PublicKey")
    }
}

impl<'a> TryFrom<&'a [u8]> for X509PublicKey<'a> {
    type Error = U2fError;

    // Must be DER bytes. If you have PEM, base64decode first!
    fn try_from(cert_der: &'a[u8]) -> Result<Self, Self::Error> {
        let cert = webpki::EndEntityCert::try_from(cert_der).map_err(|_| U2fError::BadCertificate)?;

        Ok(X509PublicKey {
            cert,
            cert_der,
        })
    }
}

// ASN.1 OID for CommonName
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

// Custom extraction of Common Name from cert
fn extract_common_name(cert_der: &[u8]) -> Option<String> {
    // This is a simplified approach - real implementation would need
    // full X.509 attribute parsing
    if let Some(subject_position) = find_sequence_after_tag(cert_der, 0x30) {
        if let Some(cn_value) = find_value_by_oid(&cert_der[subject_position..], OID_COMMON_NAME) {
            return String::from_utf8(cn_value.to_vec()).ok();
        }
    }
    None
}

// Simplified helpers for ASN.1 parsing
fn find_sequence_after_tag(data: &[u8], tag: u8) -> Option<usize> {
    for i in 0..data.len() {
        if data[i] == tag && i + 1 < data.len() {
            return Some(i + 2); // Skip tag and length
        }
    }
    None
}

// Fix find_value_by_oid function
fn find_value_by_oid<'a>(data: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    for i in 0..data.len() {
        if i + oid.len() < data.len() && data[i..i+oid.len()] == *oid {
            // Skip OID and find the actual value
            if i + oid.len() + 2 < data.len() {
                let len_byte = data[i + oid.len() + 1];
                let len = len_byte as usize;
                let start = i + oid.len() + 2;
                if start + len <= data.len() {
                    return Some(&data[start..start+len]);
                }
            }
        }
    }
    None
}

impl<'a> X509PublicKey<'a> {
    pub(crate) fn common_name(&self) -> Option<String> {
        extract_common_name(&self.cert_der)
    }

    pub(crate) fn is_secp256r1(&self) -> Result<bool, U2fError> {
        // Check if the public key is P-256
        // The SPKI data is stored within the certificate and can be examined by parsing the raw DER

        // The OID for P-256 (prime256v1) is 1.2.840.10045.3.1.7
        let secp256r1_oid = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

        // Search for the OID in the certificate DER
        for i in 0..self.cert_der.len() {
            if i + secp256r1_oid.len() <= self.cert_der.len() &&
                self.cert_der[i..i+secp256r1_oid.len()] == secp256r1_oid {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub(crate) fn verify_signature(&self, signature: &[u8], verification_data: &[u8]) -> Result<(), U2fError> {
        // Extract the public key from the certificate
        let public_key_bytes = match extract_ec_public_key_bytes(self.cert_der) {
            Some(bytes) => bytes,
            None => return Err(U2fError::BadCertificate),
        };

        // Use ring to verify the signature
        let verification_alg = &signature::ECDSA_P256_SHA256_ASN1;

        // Create a public key from the extracted bytes
        // Note: The extracted bytes may include ASN.1 structure - we need to handle that

        // Check if the key starts with the BIT STRING unused bits indicator
        let key_bytes = if public_key_bytes.len() > 1 && public_key_bytes[0] == 0x00 {
            &public_key_bytes[1..]
        } else {
            public_key_bytes
        };

        // Handle the case where we have an uncompressed point format marker
        let key_data = if key_bytes.len() > 1 && key_bytes[0] == 0x04 {
            key_bytes
        } else {
            // If we can't find a usable key format, return an error
            return Err(U2fError::BadCertificate);
        };

        let public_key = signature::UnparsedPublicKey::new(verification_alg, key_data);

        // Create the hash of the verification data
        let message_digest = digest::digest(&digest::SHA256, verification_data);

        public_key.verify(message_digest.as_ref(), signature)
            .map_err(|e| U2fError::RingError(e))?;

        Ok(())
    }
}

// Helper function to extract EC public key bytes from an X.509 certificate
fn extract_ec_public_key_bytes(cert_der: &[u8]) -> Option<&[u8]> {
    // This is a simplified approach. A real implementation would use proper ASN.1 parsing
    // We're looking for the SubjectPublicKeyInfo section which contains the public key

    // The public key is often found after the ECDSA OID
    let ecdsa_p256_oid = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1 (ecPublicKey)

    for i in 0..cert_der.len() {
        if i + ecdsa_p256_oid.len() < cert_der.len() &&
           cert_der[i..i+ecdsa_p256_oid.len()] == ecdsa_p256_oid {

            // Skip ahead to find the bit string containing the key
            // This is simplified and might need adjustment for different certificates
            for j in i..cert_der.len() {
                if j + 3 < cert_der.len() && cert_der[j] == 0x03 { // BIT STRING tag
                    let len = cert_der[j+1] as usize;
                    if j + 2 + len <= cert_der.len() {
                        // The first byte of bit string is unused bits count (usually 0x00)
                        return Some(&cert_der[j+2..j+2+len]);
                    }
                }
            }
        }
    }

    // Fallback: try to find any bit string that might contain a public key
    for i in 0..cert_der.len() {
        if i + 3 < cert_der.len() && cert_der[i] == 0x03 { // BIT STRING tag
            if cert_der[i+1] < 0x80 { // Simple length encoding (not long form)
                let len = cert_der[i+1] as usize;
                if i + 2 + len <= cert_der.len() && len > 2 {
                    // Return the bit string content
                    return Some(&cert_der[i+2..i+2+len]);
                }
            }
        }
    }

    None
}

pub struct NISTP256Key {
    /// The key's public X coordinate.
    pub x: [u8; 32],
    /// The key's public Y coordinate.
    pub y: [u8; 32],
}

impl NISTP256Key {
    pub fn from_bytes(public_key_bytes: &[u8]) -> Result<Self, U2fError> {
        if public_key_bytes.len() != 65 {
            return Err(U2fError::InvalidPublicKey);
        }

        if public_key_bytes[0] != 0x04 {
            return Err(U2fError::InvalidPublicKey);
        }

        let mut x: [u8; 32] = Default::default();
        x.copy_from_slice(&public_key_bytes[1..=32]);

        let mut y: [u8; 32] = Default::default();
        y.copy_from_slice(&public_key_bytes[33..=64]);

        Ok(NISTP256Key { x, y })
    }

    // Convert the key to uncompressed point format
    fn to_uncompressed_point(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(65);
        result.push(0x04); // Uncompressed point format tag
        result.extend_from_slice(&self.x);
        result.extend_from_slice(&self.y);
        result
    }

    #[allow(dead_code)]
    // Create a DER-encoded SPKI (SubjectPublicKeyInfo) for this P-256 key
    fn to_spki(&self) -> Vec<u8> {
        // Fixed ASN.1 DER prefix for P-256 EC public key
        let prefix = [
            0x30, 0x59, // SEQUENCE, length 89 bytes
                0x30, 0x13, // SEQUENCE, length 19 bytes
                    0x06, 0x07, // OBJECT IDENTIFIER, length 7 bytes
                        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1 (ecPublicKey)
                    0x06, 0x08, // OBJECT IDENTIFIER, length 8 bytes
                        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7 (prime256v1)
                0x03, 0x42, // BIT STRING, length 66 bytes
                    0x00, // 0 unused bits
        ];

        let mut result = Vec::with_capacity(prefix.len() + 65);
        result.extend_from_slice(&prefix);
        result.extend_from_slice(&self.to_uncompressed_point());
        result
    }

    pub fn verify_signature(&self, signature: &[u8], verification_data: &[u8]) -> Result<bool, U2fError> {
        // Create public key from the raw components
        let point = self.to_uncompressed_point();

        // Create digest of the verification data
        let message_digest = digest::digest(&digest::SHA256, verification_data);

        // Verify the signature
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            &point
        );

        match public_key.verify(message_digest.as_ref(), signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false), // Verification failed but not due to an error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;
    use std::fs::File;
    use std::io::Read;
    // use base64::{Engine as _, engine::general_purpose};
    use std::fs;
    use std::process::Command;
    use std::path::Path;

    // First, let's make sure we generate test files before running other tests
    #[test]
    fn test_01_generate_test_files() {
        let test_dir = Path::new("tests/data");
        if !test_dir.exists() {
            fs::create_dir_all(test_dir).expect("Failed to create test directory");
        }

        // Generate a simple file for testing if it doesn't exist
        let verification_data_path = Path::new("tests/data/verification_data.bin");
        if !verification_data_path.exists() {
            fs::write(verification_data_path, b"test verification data").expect("Failed to write verification data");
        }

        // Generate EC key pair if it doesn't exist
        let ec_key_path = Path::new("tests/data/test_key.pem");
        if !ec_key_path.exists() {
            let output = Command::new("openssl")
                .args(&["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out"])
                .arg(ec_key_path)
                .output()
                .expect("Failed to generate EC key");

            if !output.status.success() {
                panic!("Failed to generate EC key: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        // Export public key
        let pub_key_path = Path::new("tests/data/test_pub.pem");
        if !pub_key_path.exists() {
            let output = Command::new("openssl")
                .args(&["ec", "-in"])
                .arg(ec_key_path)
                .args(&["-pubout", "-outform", "pem", "-out"])
                .arg(pub_key_path)
                .output()
                .expect("Failed to export public key");

            if !output.status.success() {
                panic!("Failed to export public key: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        // Create certificates
        let cert_files = [
            ("cert_p256.pem", "req -x509 -newkey ec:tests/data/ecparam.pem -keyout /dev/null -out", "/CN=example.com"),
            ("cert_not_p256.pem", "req -x509 -newkey rsa:2048 -keyout /dev/null -out", "/O=TestOrg"),
            ("cert_with_cn.pem", "req -x509 -newkey rsa:2048 -keyout /dev/null -out", "/CN=example.com"),
            ("cert_without_cn.pem", "req -x509 -newkey rsa:2048 -keyout /dev/null -out", "/O=TestOrg"),
            ("valid_cert.pem", "req -x509 -key tests/data/test_key.pem -out", "/CN=test.example.com")
        ];

        // Create EC param file for cert generation
        fs::write("tests/data/ecparam.pem", "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n")
            .expect("Failed to write EC parameters");

        for (cert_file, cmd_args, subject) in cert_files.iter() {
            let cert_path = Path::new("tests/data").join(cert_file);
            if !cert_path.exists() {
                let args_vec: Vec<&str> = cmd_args.split_whitespace().collect();
                let mut command = Command::new("openssl");

                for arg in args_vec {
                    command.arg(arg);
                }
                command.arg(&cert_path);
                command.args(&["-nodes", "-subj", subject]);

                let output = command.output()
                    .expect(&format!("Failed to execute: openssl {}", cmd_args));

                if !output.status.success() {
                    panic!("Command failed: openssl {}\nError: {}",
                           cmd_args,
                           String::from_utf8_lossy(&output.stderr));
                }
            }

            // Convert to DER
            let der_path = cert_path.with_extension("der");
            if !der_path.exists() {
                let output = Command::new("openssl")
                    .args(&["x509", "-in"])
                    .arg(&cert_path)
                    .args(&["-outform", "der", "-out"])
                    .arg(&der_path)
                    .output()
                    .expect("Failed to convert to DER");

                if !output.status.success() {
                    panic!("Failed to convert to DER: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
        }

        // Create test certificate that matches our test key
        let test_cert_path = Path::new("tests/data/test_cert.der");
        if !test_cert_path.exists() {
            fs::copy("tests/data/valid_cert.der", test_cert_path).expect("Failed to copy test certificate");
        }

        // Generate signature with the key
        let signature_path = Path::new("tests/data/valid_signature.bin");
        if !signature_path.exists() {
            let output = Command::new("openssl")
                .args(&["dgst", "-sha256", "-sign"])
                .arg(ec_key_path)
                .args(&["-out"])
                .arg(signature_path)
                .arg(verification_data_path)
                .output()
                .expect("Failed to create signature");

            if !output.status.success() {
                panic!("Failed to create signature: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        // Copy signature for P256 test
        let p256_sig_path = Path::new("tests/data/valid_p256_signature.bin");
        if !p256_sig_path.exists() {
            fs::copy(signature_path, p256_sig_path).expect("Failed to copy signature");
        }

        // Export public key in raw format for test
        let pub_raw_path = Path::new("tests/data/test_pub_raw.bin");
        if !pub_raw_path.exists() {
            let output = Command::new("openssl")
                .args(&["ec", "-in"])
                .arg(ec_key_path)
                .args(&["-pubout", "-outform", "DER", "-out", "tests/data/pubkey.der"])
                .output()
                .expect("Failed to export public key as DER");

            if !output.status.success() {
                panic!("Failed to export public key as DER: {}", String::from_utf8_lossy(&output.stderr));
            }

            // Extract the raw key from DER
            let mut file = File::open("tests/data/pubkey.der").expect("Failed to open DER public key");
            let mut der = Vec::new();
            file.read_to_end(&mut der).expect("Failed to read DER");

            // Find the uncompressed point (this is a simplification)
            for i in 0..der.len() {
                if i+64 < der.len() && der[i] == 0x04 && (der[i-1] == 0x00 || der[i-2] == 0x04) {
                    fs::write(pub_raw_path, &der[i..i+65]).expect("Failed to write raw key");
                    break;
                }
            }
        }
    }

    // Helper to read test files
    fn read_test_file(filename: &str) -> Vec<u8> {
        let mut file = File::open(format!("tests/data/{}", filename))
            .unwrap_or_else(|_| panic!("Failed to open test file: {}", filename));
        let mut data = Vec::new();
        file.read_to_end(&mut data).expect("Failed to read test file");
        data
    }

    // // Helper to decode base64 test data
    // fn decode_base64(data: &str) -> Vec<u8> {
    //     general_purpose::STANDARD.decode(data).expect("Failed to decode base64")
    // }

    #[test]
    fn test_x509_from_der() {
        // Test with a valid certificate DER
        let cert_der = read_test_file("test_cert.der");
        let result = X509PublicKey::try_from(cert_der.as_slice());
        assert!(result.is_ok(), "Failed to parse valid certificate DER");

        // Test with invalid data
        let invalid_data = vec![0x01, 0x02, 0x03]; // Too short to be a valid DER
        let result = X509PublicKey::try_from(invalid_data.as_slice());
        assert!(result.is_err(), "Should fail with invalid certificate data");
    }

    #[test]
    fn test_x509_common_name() {
        // Certificates with known common names
        let cert_with_cn = read_test_file("cert_with_cn.der");
        let cert = X509PublicKey::try_from(cert_with_cn.as_slice()).expect("Valid certificate");
        let cn = cert.common_name();
        assert!(cn.is_some(), "Common name should be extracted");
        assert_eq!(cn.unwrap(), "example.com", "Common name should match expected value");

        // Certificate without a common name
        let cert_without_cn = read_test_file("cert_without_cn.der");
        let cert = X509PublicKey::try_from(cert_without_cn.as_slice()).expect("Valid certificate");
        let cn = cert.common_name();
        assert!(cn.is_none(), "No common name should be extracted");
    }

    #[test]
    fn test_x509_is_secp256r1() {
        // Certificate with secp256r1 key
        let cert_p256 = read_test_file("cert_p256.der");
        let cert = X509PublicKey::try_from(cert_p256.as_slice()).expect("Valid certificate");
        let result = cert.is_secp256r1();
        assert!(result.is_ok(), "Should not error");
        assert!(result.unwrap(), "Certificate should use secp256r1");

        // Certificate with a different key type (e.g., RSA or secp384r1)
        let cert_not_p256 = read_test_file("cert_not_p256.der");
        let cert = X509PublicKey::try_from(cert_not_p256.as_slice()).expect("Valid certificate");
        let result = cert.is_secp256r1();
        assert!(result.is_ok(), "Should not error");
        assert!(!result.unwrap(), "Certificate should not use secp256r1");
    }

    #[test]
    fn test_x509_verify_signature() {
        // Skip this test if we're not on a system with openssl available
        if !Path::new("tests/data/valid_signature.bin").exists() {
            println!("Skipping test_x509_verify_signature because test files are not available");
            return;
        }

        // Valid certificate with known valid signature
        let cert_der = read_test_file("valid_cert.der");
        let cert = X509PublicKey::try_from(cert_der.as_slice()).expect("Valid certificate");

        let signature = read_test_file("valid_signature.bin");
        let verification_data = read_test_file("verification_data.bin");

        // Extract the public key
        let key_bytes = extract_ec_public_key_bytes(&cert_der).expect("Should extract key bytes");
        println!("Extracted key bytes: {:02X?}", key_bytes);

        // Manual verification using the key_bytes
        let verification_alg = &signature::ECDSA_P256_SHA256_ASN1;
        let public_key = signature::UnparsedPublicKey::new(verification_alg, key_bytes);

        let message_digest = digest::digest(&digest::SHA256, &verification_data);

        let manual_result = public_key.verify(message_digest.as_ref(), &signature);
        println!("Manual verification result: {:?}", manual_result);

        // Test the wrapper
        match cert.verify_signature(&signature, &verification_data) {
            Ok(()) => println!("Verification succeeded"),
            Err(e) => panic!("Verification failed: {:?}", e),
        }
    }

    #[test]
    fn test_nistp256key_from_bytes() {
        // Valid EC point
        let valid_point = read_test_file("test_pub_raw.bin");
        let result = NISTP256Key::from_bytes(&valid_point);
        assert!(result.is_ok(), "Valid EC point should parse successfully");

        // Invalid length
        let invalid_length = vec![0x04; 64]; // Not 65 bytes
        let result = NISTP256Key::from_bytes(&invalid_length);
        assert!(result.is_err(), "EC point with invalid length should fail");
        match result {
            Err(U2fError::InvalidPublicKey) => (),
            _ => panic!("Expected InvalidPublicKey error"),
        }

        // Invalid format prefix (not 0x04)
        let mut invalid_format = vec![0x00; 65];
        invalid_format[0] = 0x03; // Not uncompressed format
        let result = NISTP256Key::from_bytes(&invalid_format);
        assert!(result.is_err(), "EC point with invalid format should fail");
        match result {
            Err(U2fError::InvalidPublicKey) => (),
            _ => panic!("Expected InvalidPublicKey error"),
        }
    }

    #[test]
    fn test_nistp256key_to_uncompressed_point() {
        // Create a key with known coordinates
        let x = [0x11; 32];
        let y = [0x22; 32];
        let key = NISTP256Key { x, y };

        // Convert to uncompressed point format
        let point = key.to_uncompressed_point();

        assert_eq!(point.len(), 65, "Uncompressed point should be 65 bytes");
        assert_eq!(point[0], 0x04, "Uncompressed point should start with 0x04");
        assert_eq!(&point[1..33], &x, "X coordinate should match");
        assert_eq!(&point[33..65], &y, "Y coordinate should match");
    }

    #[test]
    fn test_nistp256key_to_spki() {
        // Create a key with known coordinates
        let x = [0x11; 32];
        let y = [0x22; 32];
        let key = NISTP256Key { x, y };

        // Convert to SPKI format
        let spki = key.to_spki();

        // Test minimal SPKI structure
        assert!(spki.len() > 65, "SPKI should be longer than just the point");
        assert_eq!(spki[0], 0x30, "SPKI should start with SEQUENCE tag");

        // Check that the point is included
        let point = key.to_uncompressed_point();

        // Find the point in the SPKI
        let mut found = false;
        for i in 0..spki.len()-65 {
            if spki[i..i+65] == point[..] {
                found = true;
                break;
            }
        }
        assert!(found, "SPKI should contain the EC point");
    }

    #[test]
    fn test_nistp256key_verify_signature() {
        // Skip this test if we're not on a system with openssl available
        if !Path::new("tests/data/valid_p256_signature.bin").exists() {
            println!("Skipping test_nistp256key_verify_signature because test files are not available");
            return;
        }

        // Valid key, signature and data
        let key_bytes = read_test_file("test_pub_raw.bin");
        let key = NISTP256Key::from_bytes(&key_bytes).expect("Valid EC key");

        let signature = read_test_file("valid_p256_signature.bin");
        let verification_data = read_test_file("verification_data.bin");

        let result = key.verify_signature(&signature, &verification_data);
        assert!(result.is_ok(), "Verification should not error");
        assert!(result.unwrap(), "Valid signature should verify successfully");

        // Test with invalid signature (modify a byte)
        let mut invalid_signature = signature.clone();
        if !invalid_signature.is_empty() {
            invalid_signature[0] ^= 0xFF; // Flip bits in first byte
        }
        let result = key.verify_signature(&invalid_signature, &verification_data);
        assert!(result.is_ok(), "Verification should not error");
        assert!(!result.unwrap(), "Invalid signature should fail verification");
    }

    #[test]
    fn test_extract_ec_public_key_bytes() {
        // Test with known certificate containing EC key
        let cert_der = read_test_file("cert_p256.der");
        let key_bytes = extract_ec_public_key_bytes(&cert_der);
        assert!(key_bytes.is_some(), "EC key should be extracted from certificate");

        let key_bytes = key_bytes.unwrap();
        assert!(key_bytes.len() > 0, "Extracted key should not be empty");
        // The first byte might be 0x00 in some encodings (unused bits)
        // followed by 0x04 for uncompressed point
        assert!(key_bytes[0] == 0x04 ||
                (key_bytes.len() > 1 && key_bytes[0] == 0x00 && key_bytes[1] == 0x04),
                "EC key should be in uncompressed format or have unused bits prefix");

        // Test with certificate not containing EC key
        let cert_der = read_test_file("cert_not_p256.der");
        let key_bytes = extract_ec_public_key_bytes(&cert_der);
        // For non-EC keys, we expect the function to still return something
        // but we don't validate the content
        assert!(key_bytes.is_some(), "Should extract something from non-EC key");
    }
}
