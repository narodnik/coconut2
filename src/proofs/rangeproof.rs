use bls12_381 as bls;
use itertools::izip;
use std::io;

use crate::bls_extensions::*;
use crate::error::Result;
use crate::parameters::*;
use crate::proofs::proof::*;
use crate::proofs::simple_or;
use crate::serial::{Decodable, Encodable};

const BIT_SIZE: usize = 64;

fn summate<'a, I>(iter: I) -> bls::Scalar
where
    I: Iterator<Item = &'a bls::Scalar>,
{
    iter.fold(bls::Scalar::zero(), |acc, item| acc + item)
}

pub struct Builder<'a> {
    bit_builders: Vec<simple_or::Builder<'a>>,
    bit_commits: Vec<bls::G1Projective>,
}

pub struct Commitments<'a> {
    commitments: Vec<Box<dyn ProofCommitments + 'a>>,
}

pub struct Proof {
    proofs: Vec<simple_or::Proof>,
    bit_commits: Vec<bls::G1Projective>,
}

impl<'a> Builder<'a> {
    pub fn new<R: RngInstance>(params: &'a Parameters<R>, blind: &bls::Scalar, value: u64) -> Self {
        let mut blind_parts = params.random_scalars(BIT_SIZE);

        //let sum = blinds.iter().skip(1).sum::<bls::Scalar>();
        let sum = summate(blind_parts.iter().skip(1));
        blind_parts[0] = blind - sum;

        assert_eq!(summate(blind_parts.iter()), *blind);

        let mut bit_builders = Vec::with_capacity(BIT_SIZE);
        let mut bit_commits = Vec::with_capacity(BIT_SIZE);

        for i in 0..BIT_SIZE {
            let bit_2i = 1 << i;
            let bit_value = value & bit_2i;
            let index = if bit_value > 0 { 1 } else { 0 };

            let bit_value_scalar = bls::Scalar::from(bit_value);

            // Either the second part is zero or non-zero
            let bit_commit = params.g1 * blind_parts[i] + params.hs[0] * bit_value_scalar;
            if index == 0 {
                assert_eq!(bit_commit, params.g1 * blind_parts[i]);
            }
            bit_commits.push(bit_commit.clone());

            let commit_2i = bit_commit - params.hs[0] * bls::Scalar::from(bit_2i);
            let public_keys = vec![bit_commit, commit_2i];

            let builder = simple_or::Builder::new(params, public_keys, blind_parts[i], index);
            bit_builders.push(builder);
        }

        assert_eq!(
            bit_commits
                .iter()
                .fold(bls::G1Projective::identity(), |acc, item| acc + item),
            params.g1 * blind + params.hs[0] * bls::Scalar::from(value)
        );

        Self {
            bit_builders,
            bit_commits,
        }
    }

    pub fn commitments(&self) -> Box<dyn ProofCommitments + 'a> {
        Box::new(Commitments {
            commitments: self
                .bit_builders
                .iter()
                .map(|builder| builder.commitments())
                .collect(),
        })
    }

    pub fn finish(self, challenge: &bls::Scalar) -> Proof {
        Proof {
            proofs: self
                .bit_builders
                .into_iter()
                .map(|builder| builder.finish(challenge))
                .collect(),
            bit_commits: self.bit_commits,
        }
    }

    pub fn decode<D: io::Read, R: RngInstance>(
        mut d: D,
        params: &'a Parameters<R>,
    ) -> Result<Self> {
        Ok(Self {
            bit_builders: simple_or::DecodableVec::decode(&mut d, params)?,
            bit_commits: Decodable::decode(d)?,
        })
    }
}

impl<'a> Encodable for Builder<'a> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.bit_builders.encode(&mut s)?;
        Ok(len + self.bit_commits.encode(s)?)
    }
}

impl<'a> ProofCommitments for Commitments<'a> {
    fn commit(&self, hasher: &mut HasherToScalar) {
        for commitment in &self.commitments {
            commitment.commit(hasher);
        }
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
    ) -> Box<dyn ProofCommitments + 'a> {
        Box::new(Commitments {
            commitments: izip!(&self.proofs, &self.bit_commits)
                .enumerate()
                .map(|(i, (proof, bit_commit))| {
                    let bit_2i = 1 << i;
                    let commit_2i = bit_commit - params.hs[0] * bls::Scalar::from(bit_2i);
                    let public_keys = vec![bit_commit.clone(), commit_2i];

                    proof.commitments(params, challenge, &public_keys)
                })
                .collect(),
        })
    }

    pub fn value_commit(&self) -> bls::G1Projective {
        self.bit_commits
            .iter()
            .fold(bls::G1Projective::identity(), |acc, item| acc + item)
    }
}

impl Encodable for Proof {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.proofs.encode(&mut s)?;
        Ok(len + self.bit_commits.encode(s)?)
    }
}

impl Decodable for Proof {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            proofs: Decodable::decode(&mut d)?,
            bit_commits: Decodable::decode(d)?,
        })
    }
}

#[test]
fn test_rangeproof() {
    let params = Parameters::<OsRngInstance>::new(2);

    let blind = params.random_scalar();
    let value = 127832u64;
    let value_commit = params.g1 * blind + params.hs[0] * bls::Scalar::from(value);

    let builder = Builder::new(&params, &blind, value);
    let commits = builder.commitments();

    let mut hasher = HasherToScalar::new();
    commits.commit(&mut hasher);
    let challenge = hasher.finish();

    let proof = builder.finish(&challenge);

    assert_eq!(proof.value_commit(), value_commit);

    let commits2 = proof.commitments(&params, &challenge);
    let mut hasher2 = HasherToScalar::new();
    commits2.commit(&mut hasher2);
    let challenge2 = hasher2.finish();
    assert_eq!(challenge, challenge2);
}

#[test]
fn test_rangeproof_fail() {
    assert_eq!(BIT_SIZE, 64);
    let overflowed_value = bls::Scalar::from(u64::MAX) + bls::Scalar::one();

    let params = Parameters::<OsRngInstance>::new(2);

    let blind = params.random_scalar();
    let value_commit = params.g1 * blind + params.hs[0] * overflowed_value;

    let builder = Builder::new(&params, &blind, u64::MAX);
    let commits = builder.commitments();

    let mut hasher = HasherToScalar::new();
    commits.commit(&mut hasher);
    let challenge = hasher.finish();

    let proof = builder.finish(&challenge);

    assert_ne!(proof.value_commit(), value_commit);

    let commits2 = proof.commitments(&params, &challenge);
    let mut hasher2 = HasherToScalar::new();
    commits2.commit(&mut hasher2);
    let challenge2 = hasher2.finish();
    assert_eq!(challenge, challenge2);
}
