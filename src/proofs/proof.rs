use bls12_381 as bls;
use std::io;
use std::rc::Rc;

#[allow(unused_imports)]
use crate::bls_extensions::*;
use crate::error::Result;
#[allow(unused_imports)]
use crate::parameters::*;
use crate::serial::{Decodable, Encodable};

pub type ProofHash = bls::Scalar;

pub trait ProofBuilder {
    fn finish(&self, challenge: &bls::Scalar);
}

pub trait ProofCommitments {
    fn commit(&self, hasher: &mut HasherToScalar);
}

pub struct Witness {
    pub secret: bls::Scalar,
    witness: bls::Scalar,
}

impl Witness {
    pub fn new<R: RngInstance>(params: &Parameters<R>, secret: bls::Scalar) -> Self {
        Self {
            secret,
            witness: params.random_scalar(),
        }
    }

    pub fn get(&self) -> &bls::Scalar {
        &self.witness
    }

    pub fn derive(&self, challenge: &bls::Scalar) -> bls::Scalar {
        self.witness - challenge * self.secret
    }
}

impl Encodable for Rc<Witness> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.secret.encode(&mut s)?;
        Ok(len + self.witness.encode(s)?)
    }
}

impl Decodable for Rc<Witness> {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Rc::new(Witness {
            secret: Decodable::decode(&mut d)?,
            witness: Decodable::decode(d)?,
        }))
    }
}

#[test]
fn test_witness() {
    let params = Parameters::<OsRngInstance>::new(2);
    let secret = params.random_scalar();
    let witness = Witness::new(&params, secret.clone());

    let commit = params.g1 * witness.get();

    let mut hasher = HasherToScalar::new();
    hasher.add_g1(&commit);
    let challenge = hasher.finish();

    let response = witness.derive(&challenge);

    let public = params.g1 * secret;

    let commit2 = params.g1 * response + public * challenge;
    let mut hasher2 = HasherToScalar::new();
    hasher2.add_g1(&commit2);
    let challenge2 = hasher2.finish();

    assert_eq!(challenge, challenge2);
}
