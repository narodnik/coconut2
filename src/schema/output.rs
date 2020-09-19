use bls12_381 as bls;
use std::io;
use std::rc::Rc;

use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::elgamal::*;
use crate::error::{Error, Result};
use crate::parameters::*;
use crate::pedersen::*;
use crate::proofs::pedersen_proof;
use crate::proofs::proof::*;
use crate::proofs::rangeproof;
use crate::proofs::signature_proof;
use crate::schema::token::*;
use crate::serial::{Decodable, DecodableWithParams, Encodable};

pub struct Output {
    pub pedersen: PedersenCommit,
    pub request: OutputRequest,
    pub proofs: Option<OutputProofs>,
    pub challenge: Option<bls::Scalar>,
}

pub struct OutputRequest {
    pub sign_request: BlindSignatureRequest,
    pub gamma: ElGamalPublicKey,
    //public_attributes: Vec<bls::Scalar>,
}

pub struct OutputSignature {
    pub index: u64,
    pub signature_share: PartialSignature,
}

impl Encodable for OutputSignature {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.index.encode(&mut s)?;
        Ok(len + self.signature_share.encode(s)?)
    }
}

impl Decodable for OutputSignature {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            index: Decodable::decode(&mut d)?,
            signature_share: Decodable::decode(d)?,
        })
    }
}

pub struct OutputSecret<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    pub value: u64,
    pedersen_blind: Option<bls::Scalar>,

    signature_proof_builder: signature_proof::Builder<'a, R>,
    gamma: ElGamalPublicKey,
    commitish: bls::G1Projective,
    attribute_commit: bls::G1Projective,

    pedersen_proof_builder: Option<pedersen_proof::Builder<'a, R>>,
    rangeproof_builder: Option<rangeproof::Builder<'a>>,

    // Witnesses
    witness_signature_blind: Rc<Witness>,
    witness_serial: Rc<Witness>,
    witness_value: Rc<Witness>,
    witness_keys: Vec<Rc<Witness>>,
    witness_pedersen_blind: Option<Rc<Witness>>,
}

pub struct OutputProofCommits<'a> {
    signature: Box<dyn ProofCommitments + 'a>,
    pedersen: Box<dyn ProofCommitments + 'a>,
    rangeproof: Box<dyn ProofCommitments + 'a>,
}

pub struct OutputProofs {
    response_signature_blind: bls::Scalar,
    response_serial: bls::Scalar,
    response_value: bls::Scalar,
    response_keys: Vec<bls::Scalar>,
    response_pedersen_blind: bls::Scalar,
    pub rangeproof: rangeproof::Proof,
}

impl Output {
    pub fn new<'a, R: RngInstance>(
        coconut: &'a Coconut<R>,
        token_secret: &TokenSecret,
    ) -> (Self, OutputSecret<'a, R>) {
        let private_attributes = vec![
            Attribute::new(token_secret.serial, 0),
            Attribute::new(bls::Scalar::from(token_secret.value), 1),
        ];

        let gamma = token_secret.private_key.to_public(&coconut.params);

        let (sign_request, sign_proof_values) =
            coconut.make_blind_sign_request(&gamma, &private_attributes, &Vec::new());

        let witness_serial = Rc::new(Witness::new(&coconut.params, private_attributes[0].value));
        let witness_value = Rc::new(Witness::new(&coconut.params, private_attributes[1].value));

        let witness_signature_blind = Rc::new(Witness::new(
            &coconut.params,
            sign_proof_values.blinding_factor.clone(),
        ));
        let witness_attributes = vec![witness_serial.clone(), witness_value.clone()];
        let witness_keys: Vec<_> = sign_proof_values
            .attribute_keys
            .iter()
            .map(|key| Rc::new(Witness::new(&coconut.params, key.clone())))
            .collect();
        let attribute_indexes = vec![0, 1];

        let signature_proof_builder = signature_proof::Builder::new(
            &coconut.params,
            witness_signature_blind.clone(),
            witness_attributes.clone(),
            witness_keys.clone(),
            attribute_indexes,
        );

        let commitish = sign_proof_values.commitish;
        let attribute_commit = sign_request.attribute_commit.clone();

        (
            Self {
                pedersen: PedersenCommit::identity(),
                request: OutputRequest {
                    sign_request,
                    gamma: gamma.clone(),
                },
                proofs: None,
                challenge: None,
                //signatures: Vec::new(),
                //token: token_secret.token()
            },
            OutputSecret {
                params: &coconut.params,

                value: token_secret.value,
                pedersen_blind: None,

                signature_proof_builder,
                gamma,
                commitish,
                attribute_commit,

                pedersen_proof_builder: None,
                rangeproof_builder: None,

                witness_signature_blind,
                witness_serial,
                witness_value,
                witness_keys,
                witness_pedersen_blind: None,
            },
        )
    }

    pub fn set_proof(&mut self, proofs: OutputProofs) {
        self.proofs = Some(proofs);
    }

    pub fn unblind<R: RngInstance>(
        &self,
        coconut: &Coconut<R>,
        token_secret: &TokenSecret,
        signatures: Vec<OutputSignature>,
    ) -> Token {
        let shares: Vec<_> = signatures
            .iter()
            .map(|signature| {
                (
                    signature.index,
                    signature.signature_share.unblind(&token_secret.private_key),
                )
            })
            .collect();

        let (indexes, shares): (Vec<_>, Vec<_>) = shares.into_iter().unzip();

        let signature = Signature {
            commitish: self.request.get_hash(),
            sigma: coconut.aggregate(&shares, indexes),
        };

        //partial_token.signature = Some(signature);
        Token {
            signature: Some(signature),
        }
    }
}

impl Encodable for Output {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.pedersen.encode(&mut s)?;
        len += self.request.encode(&mut s)?;
        match &self.proofs {
            None => {
                len += 0u8.encode(&mut s)?;
            }
            Some(proofs) => {
                len += 1u8.encode(&mut s)?;
                len += proofs.encode(&mut s)?;
            }
        }
        match &self.challenge {
            None => {
                len += 0u8.encode(s)?;
            }
            Some(challenge) => {
                len += 1u8.encode(&mut s)?;
                len += challenge.encode(s)?;
            }
        }
        Ok(len)
    }
}

impl Decodable for Output {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            pedersen: Decodable::decode(&mut d)?,
            request: Decodable::decode(&mut d)?,
            proofs: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(Decodable::decode(&mut d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for output")),
            },
            challenge: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(Decodable::decode(d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for output")),
            },
        })
    }
}

impl OutputRequest {
    fn get_hash(&self) -> CommitHash {
        self.sign_request.compute_commitish()
    }
}

impl Encodable for OutputRequest {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.sign_request.encode(&mut s)?;
        Ok(len + self.gamma.encode(s)?)
    }
}

impl Decodable for OutputRequest {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            sign_request: Decodable::decode(&mut d)?,
            gamma: Decodable::decode(d)?,
        })
    }
}

impl<'a, R: RngInstance> OutputSecret<'a, R> {
    pub fn setup(&mut self, blind: bls::Scalar) {
        self.pedersen_blind = Some(blind);

        self.witness_pedersen_blind = Some(Rc::new(Witness::new(
            self.params,
            self.pedersen_blind.unwrap().clone(),
        )));

        self.pedersen_proof_builder = Some(pedersen_proof::Builder::new(
            self.params,
            self.witness_pedersen_blind.as_ref().unwrap().clone(),
            self.witness_value.clone(),
        ));

        self.rangeproof_builder = Some(rangeproof::Builder::new(
            self.params,
            &self.pedersen_blind.unwrap(),
            self.value,
        ));
    }

    pub fn proof_commits(&'a self) -> OutputProofCommits<'a> {
        assert!(self.pedersen_proof_builder.is_some());
        assert!(self.rangeproof_builder.is_some());

        OutputProofCommits {
            signature: self.signature_proof_builder.commitments(
                &self.gamma,
                &self.commitish,
                &self.attribute_commit,
            ),
            pedersen: self.pedersen_proof_builder.as_ref().unwrap().commitments(),
            rangeproof: self.rangeproof_builder.as_ref().unwrap().commitments(),
        }
    }

    pub fn finish(self, challenge: &bls::Scalar) -> OutputProofs {
        OutputProofs {
            response_signature_blind: self.witness_signature_blind.derive(challenge),
            response_serial: self.witness_serial.derive(challenge),
            response_value: self.witness_value.derive(challenge),
            response_keys: self
                .witness_keys
                .iter()
                .map(|witness| witness.derive(challenge))
                .collect(),
            response_pedersen_blind: self.witness_pedersen_blind.unwrap().derive(challenge),
            rangeproof: self.rangeproof_builder.unwrap().finish(challenge),
        }
    }
}

impl<'a, R: RngInstance> Encodable for OutputSecret<'a, R> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.value.encode(&mut s)?;
        match &self.pedersen_blind {
            None => len += 0u8.encode(&mut s)?,
            Some(blind) => {
                len += 1u8.encode(&mut s)?;
                len += blind.encode(&mut s)?;
            }
        }
        len += self.signature_proof_builder.encode(&mut s)?;
        len += self.gamma.encode(&mut s)?;
        len += self.commitish.encode(&mut s)?;
        len += self.attribute_commit.encode(&mut s)?;
        match &self.pedersen_proof_builder {
            None => len += 0u8.encode(&mut s)?,
            Some(builder) => {
                len += 1u8.encode(&mut s)?;
                len += builder.encode(&mut s)?;
            }
        }
        match &self.rangeproof_builder {
            None => len += 0u8.encode(&mut s)?,
            Some(builder) => {
                len += 1u8.encode(&mut s)?;
                len += builder.encode(&mut s)?;
            }
        }
        len += self.witness_signature_blind.encode(&mut s)?;
        len += self.witness_serial.encode(&mut s)?;
        len += self.witness_value.encode(&mut s)?;
        len += self.witness_keys.encode(&mut s)?;
        match &self.witness_pedersen_blind {
            None => len += 0u8.encode(&mut s)?,
            Some(witness) => {
                len += 1u8.encode(&mut s)?;
                len += witness.encode(&mut s)?;
            }
        }
        Ok(len)
    }
}

impl<'a, R: RngInstance> DecodableWithParams<'a, R> for OutputSecret<'a, R> {
    fn decode<D: io::Read>(mut d: D, params: &'a Parameters<R>) -> Result<Self> {
        Ok(Self {
            params,
            value: Decodable::decode(&mut d)?,
            pedersen_blind: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(Decodable::decode(&mut d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
            signature_proof_builder: DecodableWithParams::decode(&mut d, params)?,
            gamma: Decodable::decode(&mut d)?,
            commitish: Decodable::decode(&mut d)?,
            attribute_commit: Decodable::decode(&mut d)?,
            pedersen_proof_builder: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(DecodableWithParams::decode(&mut d, params)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
            rangeproof_builder: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(rangeproof::Builder::decode(&mut d, params)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
            witness_signature_blind: Decodable::decode(&mut d)?,
            witness_serial: Decodable::decode(&mut d)?,
            witness_value: Decodable::decode(&mut d)?,
            witness_keys: Decodable::decode(&mut d)?,
            witness_pedersen_blind: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(Decodable::decode(&mut d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
        })
    }
}

impl<'a> OutputProofCommits<'a> {
    pub fn commit(&self, hasher: &mut HasherToScalar) {
        self.signature.commit(hasher);
        self.pedersen.commit(hasher);
        self.rangeproof.commit(hasher);
    }

    pub fn hash(&self) -> ProofHash {
        let mut hasher = HasherToScalar::new();
        self.commit(&mut hasher);
        hasher.finish()
    }
}

/*
impl<'a, R: RngInstance> Encodable for OutputProofCommits<'a, R> {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.signature.encode(&mut s)?;
        len += self.pedersen.encode(&mut s)?;
        Ok(len + self.rangeproof.encode(s)?)
    }
}
*/

impl OutputProofs {
    pub fn commits<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        // Signature proof
        gamma: &'a ElGamalPublicKey,
        commitish: &'a bls::G1Projective,
        attribute_commit: &'a bls::G1Projective,
        encrypted_attributes: &'a Vec<EncryptedAttribute>,
        // Pedersen proof
        pedersen: &PedersenCommit,
    ) -> OutputProofCommits<'a> {
        let signature_proof = signature_proof::Proof {
            response_blind: self.response_signature_blind.clone(),
            response_attributes: vec![self.response_serial.clone(), self.response_value.clone()],
            response_keys: self.response_keys.clone(),
        };

        let pedersen_proof = pedersen_proof::Proof {
            response_blind: self.response_pedersen_blind.clone(),
            response_value: self.response_value.clone(),
        };

        let attribute_indexes = vec![0, 1];

        OutputProofCommits {
            signature: signature_proof.commitments(
                params,
                challenge,
                gamma,
                commitish,
                attribute_commit,
                encrypted_attributes,
                &attribute_indexes,
            ),
            pedersen: pedersen_proof.commitments(params, challenge, pedersen),
            rangeproof: self.rangeproof.commitments(params, challenge),
        }
    }
}

impl Encodable for OutputProofs {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.response_signature_blind.encode(&mut s)?;
        len += self.response_serial.encode(&mut s)?;
        len += self.response_value.encode(&mut s)?;
        len += self.response_keys.encode(&mut s)?;
        len += self.response_pedersen_blind.encode(&mut s)?;
        Ok(len + self.rangeproof.encode(s)?)
    }
}

impl Decodable for OutputProofs {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            response_signature_blind: Decodable::decode(&mut d)?,
            response_serial: Decodable::decode(&mut d)?,
            response_value: Decodable::decode(&mut d)?,
            response_keys: Decodable::decode(&mut d)?,
            response_pedersen_blind: Decodable::decode(&mut d)?,
            rangeproof: Decodable::decode(d)?,
        })
    }
}
