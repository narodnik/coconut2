use bls12_381 as bls;
use itertools::izip;
use std::io;
use std::rc::Rc;

use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::error::Result;
use crate::parameters::*;
use crate::proofs::proof::*;
use crate::serial::{Decodable, DecodableWithParams, Encodable};

pub struct BuilderValues {
    pub blind: bls::Scalar,
}

pub struct Builder<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    // Witnesses
    witness_attributes: Vec<Rc<Witness>>,
    witness_blind: Rc<Witness>,

    attribute_indexes: Vec<u64>,
}

pub struct Commitments<'a, R: RngInstance> {
    // Base points
    params: &'a Parameters<R>,
    verify_key: &'a VerifyKey,
    blind_commitish: &'a bls::G1Projective,

    // Commitments
    commit_kappa: bls::G2Projective,
    commit_blind: bls::G1Projective,
}

pub struct Proof {
    pub response_attributes: Vec<bls::Scalar>,
    pub response_blind: bls::Scalar,
}

impl<'a, R: RngInstance> Builder<'a, R> {
    pub fn new(
        params: &'a Parameters<R>,
        witness_attributes: Vec<Rc<Witness>>,
        witness_blind: Rc<Witness>,
        attribute_indexes: Vec<u64>,
    ) -> Self {
        Self {
            params,

            witness_attributes,
            witness_blind,

            attribute_indexes,
        }
    }

    pub fn commitments(
        &self,
        verify_key: &'a VerifyKey,
        blind_commitish: &'a bls::G1Projective,
    ) -> Box<dyn ProofCommitments + 'a> {
        assert!(self.witness_attributes.len() <= verify_key.beta.len());

        //  w_o G_2 + A + sum(w_k_i B_i)
        let mut commit_kappa = self.params.g2 * self.witness_blind.get() + verify_key.alpha;
        for (index, witness) in izip!(&self.attribute_indexes, &self.witness_attributes) {
            commit_kappa += verify_key.beta[*index as usize] * witness.get();
        }

        Box::new(Commitments {
            params: self.params,
            verify_key,
            blind_commitish,

            commit_kappa,

            commit_blind: blind_commitish * self.witness_blind.get(),
        })
    }
}

impl<'a, R: RngInstance> ProofCommitments for Commitments<'a, R> {
    fn commit(&self, hasher: &mut HasherToScalar) {
        // Add base points we use
        hasher.add_g1_affine(&self.params.g1);
        hasher.add_g2_affine(&self.params.g2);
        for h in &self.params.hs {
            hasher.add_g1_affine(h);
        }

        hasher.add_g2(&self.verify_key.alpha);
        for beta in &self.verify_key.beta {
            hasher.add_g2(beta);
        }
        hasher.add_g1(self.blind_commitish);

        hasher.add_g2(&self.commit_kappa);
        hasher.add_g1(&self.commit_blind);
    }
}

impl<'a, R: RngInstance> Encodable for Builder<'a, R> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.witness_attributes.encode(&mut s)?;
        len += self.witness_blind.encode(&mut s)?;
        Ok(len + self.attribute_indexes.encode(s)?)
    }
}

impl<'a, R: RngInstance> DecodableWithParams<'a, R> for Builder<'a, R> {
    fn decode<D: io::Read>(mut d: D, params: &'a Parameters<R>) -> Result<Self> {
        Ok(Builder {
            params,

            witness_attributes: Decodable::decode(&mut d)?,
            witness_blind: Decodable::decode(&mut d)?,
            attribute_indexes: Decodable::decode(d)?,
        })
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        verify_key: &'a VerifyKey,
        blind_commitish: &'a bls::G1Projective,
        kappa: &bls::G2Projective,
        v: &bls::G1Projective,
        attribute_indexes: &Vec<u64>,
    ) -> Box<dyn ProofCommitments + 'a> {
        // c K + r_t G2 + (1 - c) A + sum(r_m_i B_i)
        let mut commit_kappa = kappa * challenge
            + params.g2 * self.response_blind
            + verify_key.alpha * (bls::Scalar::one() - challenge);
        for (index, response) in izip!(attribute_indexes, &self.response_attributes) {
            commit_kappa += verify_key.beta[*index as usize] * response;
        }

        Box::new(Commitments {
            params,

            verify_key,
            blind_commitish,

            commit_kappa,

            commit_blind: v * challenge + blind_commitish * self.response_blind,
        })
    }
}
