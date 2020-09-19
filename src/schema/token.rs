use bls12_381 as bls;
use std::io;

use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::elgamal::*;
use crate::error::{Error, Result};
use crate::serial::{Decodable, Encodable};

pub struct Token {
    pub signature: Option<Signature>,
}

pub struct TokenSecret {
    pub value: u64,
    pub serial: bls::Scalar,
    pub private_key: ElGamalPrivateKey,
    //token: Token,
}

impl Encodable for Token {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        match &self.signature {
            None => 0u8.encode(s),
            Some(signature) => Ok(1u8.encode(&mut s)? + signature.encode(s)?),
        }
    }
}

impl Decodable for Token {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            signature: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(Decodable::decode(d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
        })
    }
}

impl TokenSecret {
    pub fn generate<R: RngInstance>(value: u64, coconut: &Coconut<R>) -> Self {
        Self {
            value,
            serial: coconut.params.random_scalar(),
            private_key: ElGamalPrivateKey::new(&coconut.params),
        }
    }
}

impl Encodable for TokenSecret {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.value.encode(&mut s)?;
        len += self.serial.encode(&mut s)?;
        len += self.private_key.encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for TokenSecret {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            value: Decodable::decode(&mut d)?,
            serial: Decodable::decode(&mut d)?,
            private_key: Decodable::decode(d)?,
        })
    }
}
