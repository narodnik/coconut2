use bls12_381 as bls;
use std::io;
use std::rc::Rc;

use crate::bls_extensions::*;
use crate::error::Result;
use crate::parameters::*;
use crate::proofs::proof::*;
use crate::serial::{Decodable, DecodableWithParams, Encodable};

pub struct Builder<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    witness: Rc<Witness>,
}

pub struct Commitments<'a, R: RngInstance> {
    params: &'a Parameters<R>,
    commit: bls::G1Projective,
}

pub struct Proof {
    pub response: bls::Scalar,
}

impl<'a, R: RngInstance> Builder<'a, R> {
    pub fn new(params: &'a Parameters<R>, witness: Rc<Witness>) -> Self {
        Self { params, witness }
    }

    pub fn commitments(&self) -> Box<dyn ProofCommitments + 'a> {
        Box::new(Commitments {
            params: self.params,
            commit: self.params.g1 * self.witness.get(),
        })
    }
}

impl<'a, R: RngInstance> ProofCommitments for Commitments<'a, R> {
    fn commit(&self, hasher: &mut HasherToScalar) {
        hasher.add_g1_affine(&self.params.g1);
        hasher.add_g1(&self.commit);
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        public: &bls::G1Projective,
    ) -> Box<dyn ProofCommitments + 'a> {
        Box::new(Commitments {
            params,
            commit: params.g1 * self.response + public * challenge,
        })
    }
}

impl<'a, R: RngInstance> Encodable for Builder<'a, R> {
    fn encode<S: io::Write>(&self, s: S) -> Result<usize> {
        self.witness.encode(s)
    }
}

impl<'a, R: RngInstance> DecodableWithParams<'a, R> for Builder<'a, R> {
    fn decode<D: io::Read>(d: D, params: &'a Parameters<R>) -> Result<Self> {
        Ok(Self {
            params,
            witness: Decodable::decode(d)?,
        })
    }
}

#[test]
fn test_ownership_proof() {
    let params = Parameters::<OsRngInstance>::new(2);

    let secret = params.random_scalar();
    let public = params.g1 * secret;

    let witness = Rc::new(Witness::new(&params, secret));

    let builder = Builder::new(&params, witness.clone());
    let commits = builder.commitments();

    let mut hasher = HasherToScalar::new();
    commits.commit(&mut hasher);
    let challenge = hasher.finish();

    let response = witness.derive(&challenge);
    let proof = Proof { response };

    let commits2 = proof.commitments(&params, &challenge, &public);
    let mut hasher2 = HasherToScalar::new();
    commits2.commit(&mut hasher2);
    let challenge2 = hasher2.finish();
    assert_eq!(challenge, challenge2);
}
