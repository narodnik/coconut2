use bls12_381 as bls;
use std::io;

use crate::bls_extensions::*;
use crate::error::Result;
use crate::parameters::*;
use crate::proofs::proof::*;
use crate::serial::VarInt;
use crate::serial::{Decodable, Encodable};

pub struct Builder<'a> {
    base: &'a bls::G1Affine,
    public_keys: Vec<bls::G1Projective>,
    secret: bls::Scalar,
    secret_index: usize,
    witness: bls::Scalar,
    responses: Vec<bls::Scalar>,
}

pub struct Commitments<'a> {
    base: &'a bls::G1Affine,
    // final commit in the entire ring
    commit: bls::G1Projective,
}

pub struct Proof {
    responses: Vec<bls::Scalar>,
}

fn hash_point(commit: &bls::G1Projective, index: u32) -> bls::Scalar {
    let mut hasher = HasherToScalar::new();
    hasher.add_g1(commit);
    hasher.add_u32(index);
    hasher.finish()
}

impl<'a> Builder<'a> {
    pub fn new<R: RngInstance>(
        params: &'a Parameters<R>,
        public_keys: Vec<bls::G1Projective>,
        secret: bls::Scalar,
        secret_index: usize,
    ) -> Self {
        assert!(secret_index < public_keys.len());
        assert_eq!(params.g1 * secret, public_keys[secret_index]);
        let public_keys_len = public_keys.len();
        Self {
            base: &params.g1,
            public_keys,
            secret,
            secret_index,
            witness: params.random_scalar(),
            responses: params.random_scalars(public_keys_len),
        }
    }

    pub fn commitments(&self) -> Box<dyn ProofCommitments + 'a> {
        let mut commit = self.base * self.witness;
        for i in (self.secret_index + 1)..self.public_keys.len() {
            let challenge = hash_point(&commit, i as u32);
            commit = self.base * self.responses[i] + self.public_keys[i] * challenge;
        }
        Box::new(Commitments {
            base: self.base,
            commit,
        })
    }

    pub fn finish(self, challenge: &bls::Scalar) -> Proof {
        let mut challenge = challenge.clone();
        for i in 0..self.secret_index {
            let commit = self.base * self.responses[i] + self.public_keys[i] * challenge;
            challenge = hash_point(&commit, (i + 1) as u32);
        }
        let mut responses = self.responses;
        responses[self.secret_index] = self.witness - challenge * self.secret;
        assert_eq!(
            self.base * responses[self.secret_index]
                + self.public_keys[self.secret_index] * challenge,
            self.base * self.witness
        );
        Proof { responses }
    }

    fn decode<D: io::Read, R: RngInstance>(mut d: D, params: &'a Parameters<R>) -> Result<Self> {
        Ok(Self {
            base: &params.g1,
            public_keys: Decodable::decode(&mut d)?,
            secret: Decodable::decode(&mut d)?,
            secret_index: u32::decode(&mut d)? as usize,
            witness: Decodable::decode(&mut d)?,
            responses: Decodable::decode(d)?,
        })
    }
}

impl<'a> Encodable for Builder<'a> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.public_keys.encode(&mut s)?;
        len += self.secret.encode(&mut s)?;
        len += (self.secret_index as u32).encode(&mut s)?;
        len += self.witness.encode(&mut s)?;
        Ok(len + self.responses.encode(s)?)
    }
}

impl<'a> Encodable for Vec<Builder<'a>> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += VarInt(self.len() as u64).encode(&mut s)?;
        for c in self.iter() {
            len += c.encode(&mut s)?;
        }
        Ok(len)
    }
}

pub trait DecodableVec<'a>: Sized {
    /// Decode an object with a well-defined format
    fn decode<D: io::Read, R: RngInstance>(d: D, params: &'a Parameters<R>) -> Result<Self>;
}

impl<'a> DecodableVec<'a> for Vec<Builder<'a>> {
    fn decode<D: io::Read, R: RngInstance>(mut d: D, params: &'a Parameters<R>) -> Result<Self> {
        let len = VarInt::decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Builder::decode(&mut d, params)?);
        }
        Ok(ret)
    }
}

impl<'a> ProofCommitments for Commitments<'a> {
    fn commit(&self, hasher: &mut HasherToScalar) {
        hasher.add_g1_affine(self.base);
        hasher.add_g1(&self.commit);
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        public_keys: &Vec<bls::G1Projective>,
    ) -> Box<dyn ProofCommitments + 'a> {
        assert_eq!(self.responses.len(), public_keys.len());
        let mut commit = bls::G1Projective::identity();
        let mut challenge = challenge.clone();
        for i in 0..public_keys.len() {
            commit = params.g1 * self.responses[i] + public_keys[i] * challenge;
            challenge = hash_point(&commit, (i + 1) as u32);
        }
        Box::new(Commitments {
            base: &params.g1,
            commit,
        })
    }
}

impl Encodable for Proof {
    fn encode<S: io::Write>(&self, s: S) -> Result<usize> {
        self.responses.encode(s)
    }
}

impl Decodable for Proof {
    fn decode<D: io::Read>(d: D) -> Result<Self> {
        Ok(Self {
            responses: Decodable::decode(d)?,
        })
    }
}

#[test]
fn test_simple_or_basic() {
    let params = Parameters::<OsRngInstance>::new(2);

    let secret = params.random_scalar();
    let public_keys = vec![
        bls::G1Projective::identity(),
        params.g1 * secret,
        bls::G1Projective::identity(),
    ];

    let builder = Builder::new(&params, public_keys.clone(), secret, 1);
    let commits = builder.commitments();

    let mut hasher = HasherToScalar::new();
    commits.commit(&mut hasher);
    let challenge = hasher.finish();

    let proof = builder.finish(&challenge);

    let commits2 = proof.commitments(&params, &challenge, &public_keys);
    let mut hasher2 = HasherToScalar::new();
    commits2.commit(&mut hasher2);
    let challenge2 = hasher2.finish();
    assert_eq!(challenge, challenge2);
}

#[test]
fn test_simple_or_zero_index() {
    let params = Parameters::<OsRngInstance>::new(2);

    let secret = params.random_scalar();
    let public_keys = vec![params.g1 * secret, bls::G1Projective::identity()];

    let builder = Builder::new(&params, public_keys.clone(), secret, 0);
    let commits = builder.commitments();

    let mut hasher = HasherToScalar::new();
    commits.commit(&mut hasher);
    let challenge = hasher.finish();

    let proof = builder.finish(&challenge);

    let commits2 = proof.commitments(&params, &challenge, &public_keys);
    let mut hasher2 = HasherToScalar::new();
    commits2.commit(&mut hasher2);
    let challenge2 = hasher2.finish();
    assert_eq!(challenge, challenge2);
}
