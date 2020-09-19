use bls12_381 as bls;
use std::io;
use std::rc::Rc;

use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::error::{Error, Result};
use crate::parameters::*;
use crate::pedersen::*;
use crate::proofs::credential_proof;
use crate::proofs::ownership_proof;
use crate::proofs::pedersen_proof;
use crate::proofs::proof::*;
use crate::proofs::rangeproof;
use crate::schema::token::*;
use crate::serial::{Decodable, DecodableWithParams, Encodable};

pub struct Input {
    pub pedersen: PedersenCommit,
    pub request: InputRequest,
    pub proofs: Option<InputProofs>,
}

pub struct InputRequest {
    pub burn_value: bls::G1Projective,
    pub credential: Credential,
}

pub struct InputSecret<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    pub value: u64,
    pedersen_blind: Option<bls::Scalar>,

    credential_proof_builder: credential_proof::Builder<'a, R>,
    verify_key: &'a VerifyKey,
    credential_blind_commitish: CommitHash,

    serial_proof_builder: ownership_proof::Builder<'a, R>,
    pedersen_proof_builder: Option<pedersen_proof::Builder<'a, R>>,
    rangeproof_builder: Option<rangeproof::Builder<'a>>,

    // Witnesses
    witness_serial: Rc<Witness>,
    witness_value: Rc<Witness>,
    witness_credential_blind: Rc<Witness>,
    witness_pedersen_blind: Option<Rc<Witness>>,
}

pub struct InputProofCommits<'a> {
    credential: Box<dyn ProofCommitments + 'a>,
    serial: Box<dyn ProofCommitments + 'a>,
    pedersen: Box<dyn ProofCommitments + 'a>,
    rangeproof: Box<dyn ProofCommitments + 'a>,
}

pub struct InputProofs {
    response_serial: bls::Scalar,
    response_value: bls::Scalar,
    response_credential_blind: bls::Scalar,
    response_pedersen_blind: bls::Scalar,
    pub rangeproof: rangeproof::Proof,
}

impl Input {
    pub fn new<'a, R: RngInstance>(
        coconut: &'a Coconut<R>,
        verify_key: &'a VerifyKey,
        token: &Token,
        token_secret: &TokenSecret,
    ) -> (Self, InputSecret<'a, R>) {
        let burn_value = coconut.params.g1 * token_secret.serial;

        let private_attributes = vec![
            Attribute::new(token_secret.serial, 0),
            Attribute::new(bls::Scalar::from(token_secret.value), 1),
        ];

        let token_signature = &token.signature.as_ref().unwrap();
        let (credential, credential_proof_values) =
            coconut.make_credential(verify_key, token_signature, &private_attributes);

        assert!(credential.verify(&coconut.params, verify_key, &Vec::new()));

        let witness_serial = Rc::new(Witness::new(&coconut.params, private_attributes[0].value));
        let witness_value = Rc::new(Witness::new(&coconut.params, private_attributes[1].value));

        let witness_attributes = vec![witness_serial.clone(), witness_value.clone()];
        let witness_credential_blind =
            Rc::new(Witness::new(&coconut.params, credential_proof_values.blind));

        let attribute_indexes = vec![0, 1];

        let credential_proof_builder = credential_proof::Builder::new(
            &coconut.params,
            witness_attributes,
            witness_credential_blind.clone(),
            attribute_indexes,
        );

        let credential_blind_commitish = credential.blind_commitish.clone();

        let serial_proof_builder =
            ownership_proof::Builder::new(&coconut.params, witness_serial.clone());

        (
            Self {
                pedersen: PedersenCommit::identity(),
                request: InputRequest {
                    burn_value,
                    credential,
                },
                proofs: None,
            },
            InputSecret {
                params: &coconut.params,

                value: token_secret.value,
                pedersen_blind: None,

                credential_proof_builder,
                credential_blind_commitish,
                verify_key,

                serial_proof_builder,
                pedersen_proof_builder: None,
                rangeproof_builder: None,

                witness_serial,
                witness_value,
                witness_credential_blind,
                witness_pedersen_blind: None,
            },
        )
    }

    pub fn set_proof(&mut self, proofs: InputProofs) {
        self.proofs = Some(proofs);
    }

    // Convenience function
    pub fn credential(&self) -> Credential {
        self.request.credential.clone()
    }
}

impl Encodable for Input {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.pedersen.encode(&mut s)?;
        len += self.request.encode(&mut s)?;
        match &self.proofs {
            None => {
                len += 0u8.encode(s)?;
            }
            Some(proofs) => {
                len += 1u8.encode(&mut s)?;
                len += proofs.encode(s)?;
            }
        }
        Ok(len)
    }
}

impl Decodable for Input {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        let pedersen: PedersenCommit = Decodable::decode(&mut d)?;
        let request: InputRequest = Decodable::decode(&mut d)?;
        let option: u8 = Decodable::decode(&mut d)?;
        Ok(Self {
            pedersen,
            request,
            proofs: match option {
                0u8 => None,
                1u8 => Some(Decodable::decode(d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
        })
    }
}

impl Encodable for InputRequest {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.burn_value.encode(&mut s)?;
        Ok(len + self.credential.encode(s)?)
    }
}

impl Decodable for InputRequest {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            burn_value: Decodable::decode(&mut d)?,
            credential: Decodable::decode(d)?,
        })
    }
}

impl<'a, R: RngInstance> InputSecret<'a, R> {
    pub fn setup(&mut self, blind: bls::Scalar) {
        self.pedersen_blind = Some(blind);

        self.witness_pedersen_blind = Some(Rc::new(Witness::new(
            self.params,
            self.pedersen_blind.unwrap().clone(),
        )));

        // Debug
        //println!("input_secret.setup(): blind = {:?}", blind);
        //println!("input_secret.setup(): value = {:?}", self.witness_value.secret);
        //let pedersen = compute_pedersen(
        //    self.params,
        //    &witness_blind.secret,
        //    &self.witness_value.secret,
        //);
        //println!("input_secret.new: {:?}", pedersen);

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

    pub fn proof_commits(&'a self) -> InputProofCommits<'a> {
        assert!(self.pedersen_proof_builder.is_some());
        assert!(self.rangeproof_builder.is_some());

        InputProofCommits {
            credential: self
                .credential_proof_builder
                .commitments(self.verify_key, &self.credential_blind_commitish),
            serial: self.serial_proof_builder.commitments(),
            pedersen: self.pedersen_proof_builder.as_ref().unwrap().commitments(),
            rangeproof: self.rangeproof_builder.as_ref().unwrap().commitments(),
        }
    }

    pub fn finish(self, challenge: &bls::Scalar) -> InputProofs {
        InputProofs {
            response_serial: self.witness_serial.derive(challenge),
            response_value: self.witness_value.derive(challenge),
            response_credential_blind: self.witness_credential_blind.derive(challenge),
            response_pedersen_blind: self.witness_pedersen_blind.unwrap().derive(challenge),
            rangeproof: self.rangeproof_builder.unwrap().finish(challenge),
        }
    }

    pub fn decode<D: io::Read>(
        mut d: D,
        params: &'a Parameters<R>,
        verify_key: &'a VerifyKey,
    ) -> Result<Self> {
        Ok(Self {
            params,
            value: Decodable::decode(&mut d)?,
            pedersen_blind: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(Decodable::decode(&mut d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
            credential_proof_builder: DecodableWithParams::decode(&mut d, params)?,
            verify_key,
            credential_blind_commitish: Decodable::decode(&mut d)?,
            serial_proof_builder: DecodableWithParams::decode(&mut d, params)?,
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
            witness_serial: Decodable::decode(&mut d)?,
            witness_value: Decodable::decode(&mut d)?,
            witness_credential_blind: Decodable::decode(&mut d)?,
            witness_pedersen_blind: match Decodable::decode(&mut d)? {
                0u8 => None,
                1u8 => Some(Decodable::decode(&mut d)?),
                _ => return Err(Error::ParseFailed("wrong option byte for input")),
            },
        })
    }
}

impl<'a, R: RngInstance> Encodable for InputSecret<'a, R> {
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
        len += self.credential_proof_builder.encode(&mut s)?;
        len += self.credential_blind_commitish.encode(&mut s)?;
        len += self.serial_proof_builder.encode(&mut s)?;
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
        len += self.witness_serial.encode(&mut s)?;
        len += self.witness_value.encode(&mut s)?;
        len += self.witness_credential_blind.encode(&mut s)?;
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

impl<'a> InputProofCommits<'a> {
    pub fn commit(&self, hasher: &mut HasherToScalar) {
        self.credential.commit(hasher);
        self.serial.commit(hasher);
        self.pedersen.commit(hasher);
        self.rangeproof.commit(hasher);
    }

    pub fn hash(&self) -> ProofHash {
        let mut hasher = HasherToScalar::new();
        self.commit(&mut hasher);
        hasher.finish()
    }
}

impl InputProofs {
    pub fn commits<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        // Credential proof
        verify_key: &'a VerifyKey,
        credential: &'a Credential,
        // Serial proof
        serial_public: &bls::G1Projective,
        // Pedersen proof
        pedersen: &PedersenCommit,
    ) -> InputProofCommits<'a> {
        let credential_proof = credential_proof::Proof {
            response_attributes: vec![self.response_serial.clone(), self.response_value.clone()],
            response_blind: self.response_credential_blind.clone(),
        };

        let serial_proof = ownership_proof::Proof {
            response: self.response_serial.clone(),
        };

        let pedersen_proof = pedersen_proof::Proof {
            response_blind: self.response_pedersen_blind.clone(),
            response_value: self.response_value.clone(),
        };

        let attribute_indexes = vec![0, 1];

        //println!("proof.commits(): pedersen = {:?}", pedersen);
        InputProofCommits {
            credential: credential_proof.commitments(
                params,
                challenge,
                verify_key,
                &credential.blind_commitish,
                &credential.kappa,
                &credential.v,
                &attribute_indexes,
            ),
            serial: serial_proof.commitments(params, challenge, serial_public),
            pedersen: pedersen_proof.commitments(params, challenge, pedersen),
            rangeproof: self.rangeproof.commitments(params, challenge),
        }
    }
}

impl Encodable for InputProofs {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.response_serial.encode(&mut s)?;
        len += self.response_value.encode(&mut s)?;
        len += self.response_credential_blind.encode(&mut s)?;
        len += self.response_pedersen_blind.encode(&mut s)?;
        Ok(len + self.rangeproof.encode(s)?)
    }
}

impl Decodable for InputProofs {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            response_serial: Decodable::decode(&mut d)?,
            response_value: Decodable::decode(&mut d)?,
            response_credential_blind: Decodable::decode(&mut d)?,
            response_pedersen_blind: Decodable::decode(&mut d)?,
            rangeproof: Decodable::decode(d)?,
        })
    }
}
