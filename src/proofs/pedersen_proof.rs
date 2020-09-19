use bls12_381 as bls;
use std::io;
use std::rc::Rc;

use crate::bls_extensions::*;
use crate::error::Result;
use crate::parameters::*;
use crate::pedersen::*;
use crate::proofs::proof::*;
use crate::serial::{Decodable, DecodableWithParams, Encodable};

pub struct Builder<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    witness_blind: Rc<Witness>,
    witness_value: Rc<Witness>,
}

pub struct Commitments<'a, R: RngInstance> {
    params: &'a Parameters<R>,
    commit_pedersen: bls::G1Projective,
}

pub struct Proof {
    pub response_blind: bls::Scalar,
    pub response_value: bls::Scalar,
}

impl<'a, R: RngInstance> Builder<'a, R> {
    pub fn new(
        params: &'a Parameters<R>,
        witness_blind: Rc<Witness>,
        witness_value: Rc<Witness>,
    ) -> Self {
        Self {
            params,
            witness_blind,
            witness_value,
        }
    }

    pub fn commitments(&self) -> Box<dyn ProofCommitments + 'a> {
        assert!(self.params.hs.len() > 0);
        Box::new(Commitments {
            params: self.params,
            commit_pedersen: compute_pedersen(
                self.params,
                self.witness_blind.get(),
                self.witness_value.get(),
            ),
        })
    }
}

impl<'a, R: RngInstance> Encodable for Builder<'a, R> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.witness_blind.encode(&mut s)?;
        Ok(len + self.witness_value.encode(s)?)
    }
}

impl<'a, R: RngInstance> DecodableWithParams<'a, R> for Builder<'a, R> {
    fn decode<D: io::Read>(mut d: D, params: &'a Parameters<R>) -> Result<Self> {
        Ok(Self {
            params,
            witness_blind: Decodable::decode(&mut d)?,
            witness_value: Decodable::decode(&mut d)?,
        })
    }
}

impl<'a, R: RngInstance> ProofCommitments for Commitments<'a, R> {
    fn commit(&self, hasher: &mut HasherToScalar) {
        assert!(self.params.hs.len() > 0);
        hasher.add_g1_affine(&self.params.g1);
        hasher.add_g1_affine(&self.params.hs[0]);
        hasher.add_g1(&self.commit_pedersen);
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        pedersen: &bls::G1Projective,
    ) -> Box<dyn ProofCommitments + 'a> {
        assert!(params.hs.len() > 0);
        Box::new(Commitments {
            params,
            commit_pedersen: compute_pedersen(params, &self.response_blind, &self.response_value)
                + pedersen * challenge,
        })
    }
}

#[test]
fn test_pedersen_proof() {
    let params = Parameters::<OsRngInstance>::new(2);

    let blind = params.random_scalar();
    let value = bls::Scalar::from(110);
    let pedersen = params.g1 * blind + params.hs[0] * value;

    let witness_blind = Rc::new(Witness::new(&params, blind));
    let witness_value = Rc::new(Witness::new(&params, value));

    let builder = Builder::new(&params, witness_blind.clone(), witness_value.clone());
    let commits = builder.commitments();

    let mut hasher = HasherToScalar::new();
    commits.commit(&mut hasher);
    let challenge = hasher.finish();

    let response_blind = witness_blind.derive(&challenge);
    let response_value = witness_value.derive(&challenge);
    let proof = Proof {
        response_blind,
        response_value,
    };

    let commits2 = proof.commitments(&params, &challenge, &pedersen);
    let mut hasher2 = HasherToScalar::new();
    commits2.commit(&mut hasher2);
    let challenge2 = hasher2.finish();
    assert_eq!(challenge, challenge2);
}
