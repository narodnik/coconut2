use bls12_381 as bls;
use std::io;

use crate::bls_extensions::*;
use crate::error::Result;
use crate::parameters::*;
use crate::serial::{Decodable, Encodable};

pub type EncryptedValue = (bls::G1Projective, bls::G1Projective);

pub struct ElGamalPrivateKey {
    pub private_key: bls::Scalar,
}

#[derive(Clone)]
pub struct ElGamalPublicKey {
    pub public_key: bls::G1Projective,
}

impl ElGamalPrivateKey {
    pub fn new<R: RngInstance>(params: &Parameters<R>) -> Self {
        Self {
            private_key: params.random_scalar(),
        }
    }

    pub fn to_public<R: RngInstance>(&self, params: &Parameters<R>) -> ElGamalPublicKey {
        ElGamalPublicKey {
            public_key: params.g1 * self.private_key,
        }
    }

    pub fn decrypt(&self, ciphertext: &EncryptedValue) -> bls::G1Projective {
        let (a, b) = ciphertext;
        b - a * self.private_key
    }
}

impl Encodable for ElGamalPrivateKey {
    fn encode<S: io::Write>(&self, s: S) -> Result<usize> {
        Ok(self.private_key.encode(s)?)
    }
}

impl Decodable for ElGamalPrivateKey {
    fn decode<D: io::Read>(d: D) -> Result<Self> {
        Ok(Self {
            private_key: Decodable::decode(d)?,
        })
    }
}

impl ElGamalPublicKey {
    pub fn encrypt<R: RngInstance>(
        &self,
        params: &Parameters<R>,
        attribute: &bls::Scalar,
        attribute_key: &bls::Scalar,
        shared_value: &bls::G1Projective,
    ) -> EncryptedValue {
        (
            params.g1 * attribute_key,
            self.public_key * attribute_key + shared_value * attribute,
        )
    }
}

impl Encodable for ElGamalPublicKey {
    fn encode<S: io::Write>(&self, s: S) -> Result<usize> {
        self.public_key.encode(s)
    }
}

impl Decodable for ElGamalPublicKey {
    fn decode<D: io::Read>(d: D) -> Result<Self> {
        Ok(Self {
            public_key: Decodable::decode(d)?,
        })
    }
}
