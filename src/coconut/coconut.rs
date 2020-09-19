use bls12_381 as bls;
use itertools::{chain, izip};
use std::convert::TryFrom;
use std::io;

use crate::bls_extensions::*;
use crate::elgamal::*;
//use crate::error::*;
use crate::error::Result;
use crate::parameters::*;
use crate::proofs::credential_proof;
use crate::proofs::signature_proof;
use crate::serial::{Decodable, Encodable};
use crate::utility::*;

type SignatureShare = bls::G1Projective;
type CombinedSignatureShares = bls::G1Projective;

pub type CommitHash = bls::G1Projective;

pub struct SecretKey {
    pub x: bls::Scalar,
    pub y: Vec<bls::Scalar>,
}

impl Encodable for SecretKey {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.x.encode(&mut s)?;
        Ok(len + self.y.encode(s)?)
    }
}

impl Decodable for SecretKey {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            x: Decodable::decode(&mut d)?,
            y: Decodable::decode(d)?,
        })
    }
}

#[derive(Clone)]
pub struct VerifyKey {
    pub alpha: bls::G2Projective,
    pub beta: Vec<bls::G2Projective>,
}

impl Encodable for VerifyKey {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.alpha.encode(&mut s)?;
        Ok(len + self.beta.encode(s)?)
    }
}

impl Decodable for VerifyKey {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            alpha: Decodable::decode(&mut d)?,
            beta: Decodable::decode(d)?,
        })
    }
}

pub struct Attribute {
    pub value: bls::Scalar,
    pub index: u64,
}

pub struct EncryptedAttribute {
    pub value: EncryptedValue,
    pub index: u64,
}

impl Encodable for EncryptedAttribute {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.value.encode(&mut s)?;
        Ok(len + self.index.encode(s)?)
    }
}

impl Decodable for EncryptedAttribute {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            value: Decodable::decode(&mut d)?,
            index: Decodable::decode(d)?,
        })
    }
}

pub struct Coconut<R: RngInstance> {
    pub params: Parameters<R>,
    pub threshold: u32,
    authorities_total: u32,
}

pub struct BlindSignatureRequest {
    pub attribute_commit: bls::G1Projective,
    pub encrypted_attributes: Vec<EncryptedAttribute>,
}

#[derive(Clone)]
pub struct Credential {
    pub kappa: bls::G2Projective,
    pub v: bls::G1Projective,
    pub blind_commitish: CommitHash,
    pub blind_sigma: bls::G1Projective,
}

pub struct PartialSignature {
    encrypted_value: EncryptedValue,
}

impl Encodable for PartialSignature {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        self.encrypted_value.encode(&mut s)
    }
}

impl Decodable for PartialSignature {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            encrypted_value: Decodable::decode(&mut d)?,
        })
    }
}

pub struct Signature {
    pub commitish: CommitHash,
    pub sigma: bls::G1Projective,
}

impl Encodable for Signature {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.commitish.encode(&mut s)?;
        Ok(len + self.sigma.encode(s)?)
    }
}

impl Decodable for Signature {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            commitish: Decodable::decode(&mut d)?,
            sigma: Decodable::decode(d)?,
        })
    }
}

impl Attribute {
    pub fn new(value: bls::Scalar, index: u64) -> Self {
        Self { value, index }
    }
}

impl<R: RngInstance> Coconut<R> {
    pub fn new(attributes_size: u32, authorities_threshold: u32, authorities_total: u32) -> Self {
        Self {
            params: Parameters::<R>::new(attributes_size),
            threshold: authorities_threshold,
            authorities_total: authorities_total,
        }
    }

    pub fn multiparty_keygen(&self) -> (Vec<SecretKey>, Vec<VerifyKey>) {
        let attributes_size = self.params.hs.len();
        assert!(self.authorities_total >= self.threshold);
        assert!(attributes_size > 0);

        let n_random_scalars = |n| (0..n).map(|_| self.params.random_scalar()).collect();
        let v_poly: Vec<_> = n_random_scalars(self.threshold);
        let w_poly: Vec<Vec<_>> = (0..attributes_size)
            .map(|_| n_random_scalars(self.threshold))
            .collect();

        //// Generate shares
        let x_shares =
            (1..=self.authorities_total).map(|i| compute_polynomial(v_poly.iter(), i as u64));
        let y_shares = (1..=self.authorities_total).map(|i| {
            w_poly
                .iter()
                .map(move |w_coefficients| compute_polynomial(w_coefficients.iter(), i as u64))
        });

        // Set the keys
        // sk_i = (x, (y_1, y_2, ..., y_q))
        // vk_i = (g2^x, (g2^y_1, g2^y_2, ..., g2^y_q)) = (a, (B_1, B_2, ..., B_q))
        let verify_keys: Vec<VerifyKey> = x_shares
            .clone()
            .zip(y_shares.clone())
            .map(|(x, y_share_parts)| VerifyKey {
                alpha: self.params.g2 * x,
                beta: y_share_parts.map(|y| self.params.g2 * y).collect(),
            })
            .collect();
        // We are moving out of x_shares into SecretKey, so this line happens
        // after creating verify_keys to avoid triggering borrow checker.
        let secret_keys: Vec<SecretKey> = x_shares
            .zip(y_shares)
            .map(|(x, y)| SecretKey {
                x: x,
                y: y.collect(),
            })
            .collect();

        (secret_keys, verify_keys)
    }

    pub fn aggregate_keys(&self, verify_keys: &Vec<VerifyKey>) -> VerifyKey {
        let lagrange = lagrange_basis_from_range(verify_keys.len() as u64);

        let (alpha, beta): (Vec<&_>, Vec<&Vec<_>>) = verify_keys
            .iter()
            .map(|key| (&key.alpha, &key.beta))
            .unzip();

        assert!(beta.len() > 0);
        let attributes_size = beta[0].len();

        assert_eq!(lagrange.len(), alpha.len());

        let mut aggregate_alpha = bls::G2Projective::identity();
        for (alpha_i, lagrange_i) in izip!(alpha, &lagrange) {
            aggregate_alpha += alpha_i * lagrange_i;
        }

        let aggregate_beta: Vec<_> = (0..attributes_size)
            .map(|i| {
                let mut result = bls::G2Projective::identity();
                for (beta_j, lagrange_i) in izip!(&beta, &lagrange) {
                    result += beta_j[i] * lagrange_i;
                }
                result
            })
            .collect();

        return VerifyKey {
            alpha: aggregate_alpha,
            beta: aggregate_beta,
        };
    }

    pub fn make_blind_sign_request(
        &self,
        shared_attribute_key: &ElGamalPublicKey,
        private_attributes: &Vec<Attribute>,
        public_attributes: &Vec<Attribute>,
    ) -> (BlindSignatureRequest, signature_proof::BuilderValues) {
        let blinding_factor = self.params.random_scalar();

        assert_eq!(
            self.params.hs.len(),
            private_attributes.len() + public_attributes.len()
        );

        let mut attribute_commit = self.params.g1 * blinding_factor;
        for attribute in chain(private_attributes, public_attributes) {
            let index = usize::try_from(attribute.index).unwrap();
            attribute_commit += self.params.hs[index] * attribute.value;
        }

        let commitish = compute_commitish(&attribute_commit);

        let attribute_keys: Vec<_> = (0..private_attributes.len())
            .map(|_| self.params.random_scalar())
            .collect();

        let encrypted_attributes: Vec<_> = izip!(private_attributes, &attribute_keys)
            .map(|(attribute, key)| EncryptedAttribute {
                value: shared_attribute_key.encrypt(
                    &self.params,
                    &attribute.value,
                    &key,
                    &commitish,
                ),
                index: attribute.index,
            })
            .collect();

        (
            BlindSignatureRequest {
                attribute_commit,
                encrypted_attributes,
            },
            signature_proof::BuilderValues {
                commitish,
                attribute_keys,
                blinding_factor,
            },
        )
    }

    pub fn aggregate(
        &self,
        signature_shares: &Vec<SignatureShare>,
        indexes: Vec<u64>,
    ) -> CombinedSignatureShares {
        let lagrange = lagrange_basis(indexes.iter());

        let mut signature = bls::G1Projective::identity();
        for (share, lagrange_i) in izip!(signature_shares, lagrange) {
            signature += share * lagrange_i;
        }
        signature
    }

    pub fn make_credential(
        &self,
        verify_key: &VerifyKey,
        signature: &Signature,
        attributes: &Vec<Attribute>,
    ) -> (Credential, credential_proof::BuilderValues) {
        assert!(attributes.len() <= verify_key.beta.len());

        let blind_prime = self.params.random_scalar();
        let (blind_commitish, blind_sigma) = (
            signature.commitish * blind_prime,
            signature.sigma * blind_prime,
        );

        let blind = self.params.random_scalar();

        // K = o G2 + A + sum(m_i B_i)
        let mut kappa = self.params.g2 * blind + verify_key.alpha;
        for attribute in attributes {
            kappa += verify_key.beta[attribute.index as usize] * attribute.value;
        }
        // v = r H_p(C_m)
        let v = blind_commitish * blind;

        (
            Credential {
                kappa: kappa,
                v: v,
                blind_commitish,
                blind_sigma,
            },
            credential_proof::BuilderValues { blind },
        )
    }
}

impl BlindSignatureRequest {
    pub fn compute_commitish(&self) -> CommitHash {
        compute_commitish(&self.attribute_commit)
    }

    pub fn blind_sign<R: RngInstance>(
        &self,
        params: &Parameters<R>,
        secret_key: &SecretKey,
        public_attributes: &Vec<Attribute>,
    ) -> PartialSignature {
        assert_eq!(
            self.encrypted_attributes.len() + public_attributes.len(),
            params.hs.len()
        );
        // TODO: check indexes are sane as well
        let (a_factors, b_factors): (Vec<&_>, Vec<&_>) = self
            .encrypted_attributes
            .iter()
            .map(|attr| (&attr.value.0, &attr.value.1))
            .unzip();
        // Rust doesn't have 3 way unzip so do this separately
        let indexes: Vec<_> = self
            .encrypted_attributes
            .iter()
            .map(|attr| attr.index)
            .collect();

        // Issue signature
        let commitish = self.compute_commitish();

        let mut signature_a = bls::G1Projective::identity();
        for (index, a) in izip!(&indexes, a_factors) {
            signature_a += a * secret_key.y[*index as usize];
        }

        let public_terms: Vec<_> = public_attributes
            .iter()
            .map(|attribute| commitish * attribute.value)
            .collect();
        let public_indexes: Vec<_> = public_attributes.iter().map(|attr| attr.index).collect();

        let mut signature_b = commitish * secret_key.x;
        for (index, b) in izip!(
            chain(&indexes, &public_indexes),
            chain(b_factors, &public_terms)
        ) {
            signature_b += b * secret_key.y[*index as usize];
        }

        PartialSignature {
            encrypted_value: (signature_a, signature_b),
        }
    }
}

impl Encodable for BlindSignatureRequest {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.attribute_commit.encode(&mut s)?;
        Ok(len + self.encrypted_attributes.encode(s)?)
    }
}

impl Decodable for BlindSignatureRequest {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            attribute_commit: Decodable::decode(&mut d)?,
            encrypted_attributes: Decodable::decode(d)?,
        })
    }
}

impl Credential {
    pub fn verify<'a, R: RngInstance>(
        &self,
        params: &Parameters<R>,
        verify_key: &VerifyKey,
        public_attributes: &Vec<Attribute>,
    ) -> bool {
        let mut public_aggregates = bls::G2Projective::identity();
        for attribute in public_attributes {
            public_aggregates += verify_key.beta[attribute.index as usize] * attribute.value;
        }

        let kappa = bls::G2Affine::from(self.kappa + public_aggregates);
        let blind_commit = bls::G1Affine::from(self.blind_commitish);
        let sigma_nu = bls::G1Affine::from(self.blind_sigma + self.v);
        bls::pairing(&blind_commit, &kappa) == bls::pairing(&sigma_nu, &params.g2)
    }
}

impl Encodable for Credential {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.kappa.encode(&mut s)?;
        len += self.v.encode(&mut s)?;
        len += self.blind_commitish.encode(&mut s)?;
        len += self.blind_sigma.encode(s)?;
        Ok(len)
    }
}

impl Decodable for Credential {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            kappa: Decodable::decode(&mut d)?,
            v: Decodable::decode(&mut d)?,
            blind_commitish: Decodable::decode(&mut d)?,
            blind_sigma: Decodable::decode(d)?,
        })
    }
}

impl PartialSignature {
    pub fn unblind(&self, private_key: &ElGamalPrivateKey) -> SignatureShare {
        private_key.decrypt(&self.encrypted_value)
    }
}
