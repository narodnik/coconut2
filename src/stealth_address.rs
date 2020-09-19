use bls12_381 as bls;
use sha2::{Digest, Sha256};

const RAW_PAYLOAD_SIZE: usize = 1 + 48 + 4;

pub struct StealthAddress {
    public: bls::G1Projective,
}

impl StealthAddress {
    pub fn new(public: bls::G1Projective) -> Self {
        StealthAddress { public }
    }

    pub fn from_string(address: &str) -> Option<Self> {
        // decode from base58
        let mut payload: [u8; RAW_PAYLOAD_SIZE] = [0; RAW_PAYLOAD_SIZE];
        match bs58::decode(address).into(&mut payload[..]) {
            Ok(payload_len) => {
                if payload_len < RAW_PAYLOAD_SIZE {
                    return None;
                }
            }
            Err(_) => return None,
        }

        if payload[0] != 0 {
            return None;
        }

        // create the hash for the version and public key
        let mut checksum = Sha256::new();
        checksum.input(&payload[..49]);
        let checksum = checksum.result();

        // check the checksum
        if checksum[..4] != payload[49..] {
            return None;
        }

        let mut key: [u8; 48] = [0; 48];
        key.copy_from_slice(&payload[1..49]);
        let public = bls::G1Affine::from_compressed(&key);
        // Check if the key is valid
        if bool::from(public.is_none()) {
            return None;
        }
        let public = bls::G1Projective::from(public.unwrap());

        Some(Self { public })
    }

    pub fn to_string(&self) -> String {
        let mut payload: [u8; 53] = [0; 53];
        let key = bls::G1Affine::from(self.public).to_compressed();
        let version = [0; 1];

        // add the public key and the version to the payload
        payload[1..49].copy_from_slice(&key[..]);
        payload[..1].copy_from_slice(&version[..]);

        // hash the public key and the version
        let mut checksum = Sha256::new();
        checksum.input(payload[..49].as_ref());
        let checksum = checksum.result();

        // add the first four bytes to the last bytes in the payload
        payload[49..53].copy_from_slice(&checksum[..4]);

        // encoded with base58
        let result = bs58::encode(payload.as_ref()).into_string();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_string_with_value_returned_from_to_string_method() {
        let g = bls::G1Projective::generator();
        let stealth_address = StealthAddress::new(g);
        let s = stealth_address.to_string();
        assert_eq!(g, StealthAddress::from_string(&s[..]).unwrap().public);
    }

    #[test]
    fn test_from_string_with_unvalid_version() {
        let addr = "0dUQ5BrxweVT1uAfAWZSgP7odQT7uYuwGtixyPXst8CGtZg1jTzCAje2fcTZUK9yq6hVFYfQ";
        assert!(StealthAddress::from_string(addr).is_none());
    }

    #[test]
    fn test_from_string_with_unvalid_address_size() {
        let addr = "1dUQ5BrxweVT1uAfAWZSguwGtixyPXst8CGtZg1jTzCAje2fcTZUK9yq6hVFYfQ";
        assert!(StealthAddress::from_string(addr).is_none());
    }

    #[test]
    fn test_from_string_with_unvalid_checksum() {
        let addr = "1dUQ5BrxweVT1uAfAWZSgP7odQT7uYuwGtixyPXst8CGtZg1jTzCAje2fcTZUK9yq32VFYfQ";
        assert!(StealthAddress::from_string(addr).is_none());
    }

    #[test]
    fn test_to_string() {
        let public = bls::G1Projective::generator();
        let stealth_address = StealthAddress::new(public);
        let addr = "1dUQ5BrxweVT1uAfAWZSgP7odQT7uYuwGtixyPXst8CGtZg1jTzCAje2fcTZUK9yq6hVFYfQ";
        assert_eq!(addr, stealth_address.to_string());
    }

    #[test]
    fn test_to_string_method_with_value_returned_from_method_from_string() {
        let addr = "1dUQ5BrxweVT1uAfAWZSgP7odQT7uYuwGtixyPXst8CGtZg1jTzCAje2fcTZUK9yq6hVFYfQ";
        let new_sd = StealthAddress::from_string(addr).unwrap();
        assert_eq!(addr, new_sd.to_string());
    }
}
