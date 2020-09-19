use bls12_381 as bls;
use itertools::izip;
use std::io;
use std::rc::Rc;

use crate::bls_extensions::*;
use crate::coconut::coconut::EncryptedAttribute;
use crate::elgamal::*;
use crate::error::Result;
use crate::parameters::*;
use crate::proofs::proof::*;
use crate::serial::{Decodable, DecodableWithParams, Encodable};

pub struct BuilderValues {
    pub commitish: bls::G1Projective,
    pub attribute_keys: Vec<bls::Scalar>,
    pub blinding_factor: bls::Scalar,
}

pub struct Builder<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    // Witnesses
    witness_blind: Rc<Witness>,
    witness_attributes: Vec<Rc<Witness>>,
    witness_keys: Vec<Rc<Witness>>,

    attribute_indexes: Vec<u64>,
}

pub struct Commitments<'a, R: RngInstance> {
    // Base points
    params: &'a Parameters<R>,
    gamma: &'a ElGamalPublicKey,
    commitish: &'a bls::G1Projective,

    // This value is hashed in the challenge in coconut ref impl. We do the same here.
    attribute_commit: &'a bls::G1Projective,

    // Commitments
    commit_attributes: bls::G1Projective,
    commit_keys: Vec<(bls::G1Projective, bls::G1Projective)>,
}

pub struct Proof {
    // Responses
    pub response_blind: bls::Scalar,
    pub response_attributes: Vec<bls::Scalar>,
    pub response_keys: Vec<bls::Scalar>,
}

impl<'a, R: RngInstance> Builder<'a, R> {
    pub fn new(
        params: &'a Parameters<R>,
        witness_blind: Rc<Witness>,
        witness_attributes: Vec<Rc<Witness>>,
        witness_keys: Vec<Rc<Witness>>,
        attribute_indexes: Vec<u64>,
    ) -> Self {
        assert_eq!(params.hs.len(), witness_attributes.len());

        Self {
            params,

            witness_blind,
            witness_attributes,
            witness_keys,
            attribute_indexes,
        }
    }

    pub fn commitments(
        &self,
        gamma: &'a ElGamalPublicKey,
        commitish: &'a bls::G1Projective,
        attribute_commit: &'a bls::G1Projective,
    ) -> Box<Commitments<'a, R>> {
        assert_eq!(self.witness_attributes.len(), self.params.hs.len());
        assert!(self.witness_attributes.len() >= self.witness_keys.len());

        // w_o G_1 + sum(w_m H_i)
        let mut commit_attributes = self.params.g1 * self.witness_blind.get();
        for (index, witness) in izip!(&self.attribute_indexes, &self.witness_attributes) {
            commit_attributes += self.params.hs[*index as usize] * witness.get();
        }

        Box::new(Commitments {
            params: self.params,
            gamma,
            commitish,
            attribute_commit,

            commit_attributes,

            commit_keys: izip!(&self.witness_attributes, &self.witness_keys)
                .map(|(witness_attribute, witness_key)| {
                    (
                        // w_k_i G_1
                        self.params.g1 * witness_key.get(),
                        // w_m_i h + w_k_i Y
                        commitish * witness_attribute.get()
                            + gamma.public_key * witness_key.get(),
                    )
                })
                .collect(),
        })
    }
}

impl<'a, R: RngInstance> Encodable for Builder<'a, R> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.witness_blind.encode(&mut s)?;
        len += self.witness_attributes.encode(&mut s)?;
        len += self.witness_keys.encode(&mut s)?;
        Ok(len + self.attribute_indexes.encode(s)?)
    }
}

impl<'a, R: RngInstance> DecodableWithParams<'a, R> for Builder<'a, R> {
    fn decode<D: io::Read>(mut d: D, params: &'a Parameters<R>) -> Result<Self> {
        Ok(Builder {
            params,

            witness_blind: Decodable::decode(&mut d)?,
            witness_attributes: Decodable::decode(&mut d)?,
            witness_keys: Decodable::decode(&mut d)?,
            attribute_indexes: Decodable::decode(d)?,
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
        hasher.add_g1(&self.gamma.public_key);
        hasher.add_g1(self.commitish);
        hasher.add_g1(self.attribute_commit);

        hasher.add_g1(&self.commit_attributes);

        for (commit_a, commit_b) in &self.commit_keys {
            hasher.add_g1(&commit_a);
            hasher.add_g1(&commit_b);
        }
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        gamma: &'a ElGamalPublicKey,
        commitish: &'a bls::G1Projective,
        attribute_commit: &'a bls::G1Projective,
        encrypted_attributes: &Vec<EncryptedAttribute>,
        attribute_indexes: &Vec<u64>,
    ) -> Box<Commitments<'a, R>> {
        // c c_m + r_r G_1 + sum(r_m_i H_i)
        let mut commit_attributes = attribute_commit * challenge + params.g1 * self.response_blind;
        for (index, response) in izip!(attribute_indexes, &self.response_attributes) {
            commit_attributes += params.hs[*index as usize] * response;
        }

        Box::new(Commitments {
            params,

            gamma,
            commitish,
            attribute_commit,

            commit_attributes,

            commit_keys: izip!(
                &self.response_attributes,
                &self.response_keys,
                encrypted_attributes
            )
            .map(|(response_attribute, response_key, attr)| {
                (
                    // c A_i + r_k_i G1
                    attr.value.0 * challenge + params.g1 * response_key,
                    // c B_i + r_k_i Y + r_m_i h
                    attr.value.1 * challenge
                        + gamma.public_key * response_key
                        + commitish * response_attribute,
                )
            })
            .collect(),
        })
    }
}
