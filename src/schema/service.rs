use bls12_381 as bls;

use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::error;
use crate::schema::input::*;
use crate::schema::output::*;
use crate::schema::transaction::*;

type SpentBurns = Vec<bls::G1Projective>;

pub fn generate_keys(attributes: u32, threshold: u32, total: u32) -> (Vec<SecretKey>, VerifyKey) {
    let coconut = Coconut::<OsRngInstance>::new(attributes, threshold, total);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();
    let verify_key = coconut.aggregate_keys(&verify_keys);

    (secret_keys, verify_key)
}

pub struct SigningService<'a, R: RngInstance> {
    coconut: &'a Coconut<R>,
    secret: SecretKey,
    verify_key: VerifyKey,
    pub index: u64,
    spent: SpentBurns,
}

impl<'a, R: RngInstance> SigningService<'a, R> {
    pub fn from_secret(
        coconut: &'a Coconut<R>,
        secret: SecretKey,
        verify_key: VerifyKey,
        index: u64,
    ) -> Self {
        Self {
            coconut,
            secret,
            verify_key,
            index,
            spent: SpentBurns::new(),
        }
    }

    pub fn process(
        &mut self,
        transaction: &Transaction,
    ) -> Result<Vec<OutputSignature>, error::Error> {
        if !transaction.check(self.coconut) {
            return Err(error::Error::TransactionPedersenCheckFailed);
        }

        let mut hasher = HasherToScalar::new();

        for input in &transaction.inputs {
            self.process_input(input, &transaction.challenge, &mut hasher)?;
        }

        let mut output_signatures = Vec::with_capacity(transaction.outputs.len());
        for output in &transaction.outputs {
            if output.challenge.is_none() {
                return Err(error::Error::InvalidCredential);
            }
            let signature = self.process_output(output, &output.challenge.unwrap(), &mut hasher)?;
            output_signatures.push(signature);
        }

        let challenge2 = hasher.finish();
        if transaction.challenge != challenge2 {
            return Err(error::Error::ProofsFailed);
        }

        Ok(output_signatures)
    }

    fn process_input(
        &mut self,
        input: &Input,
        challenge: &bls::Scalar,
        hasher: &mut HasherToScalar,
    ) -> Result<(), error::Error> {
        if self.spent.contains(&input.request.burn_value) {
            return Err(error::Error::TokenAlreadySpent);
        }

        if !input.request.credential.verify(
            &self.coconut.params,
            &self.verify_key,
            &Vec::new(),
            //vec![burn_commits],
        ) {
            return Err(error::Error::InputTokenVerifyFailed);
        }

        match &input.proofs {
            Some(proofs) => {
                // Rangeproof pedersen check
                if proofs.rangeproof.value_commit() != input.pedersen {
                    return Err(error::Error::RangeproofPedersenMatchFailed);
                }

                // Validate remaining proofs
                let commits = proofs.commits(
                    &self.coconut.params,
                    challenge,
                    &self.verify_key,
                    &input.request.credential,
                    &input.request.burn_value,
                    &input.pedersen,
                );

                //commits.commit(hasher);
                hasher.add(commits.hash());
            }
            None => {
                return Err(error::Error::MissingProofs);
            }
        }

        // To avoid double spends of the same coin
        self.spent.push(input.request.burn_value);

        Ok(())
    }

    fn process_output(
        &self,
        output: &Output,
        challenge: &bls::Scalar,
        hasher: &mut HasherToScalar,
    ) -> Result<OutputSignature, error::Error> {
        match &output.proofs {
            Some(proofs) => {
                // Rangeproof pedersen check
                if proofs.rangeproof.value_commit() != output.pedersen {
                    return Err(error::Error::RangeproofPedersenMatchFailed);
                }

                let commitish = output.request.sign_request.compute_commitish();

                // Validate remaining proofs
                let commits = proofs.commits(
                    &self.coconut.params,
                    challenge,
                    &output.request.gamma,
                    &commitish,
                    &output.request.sign_request.attribute_commit,
                    &output.request.sign_request.encrypted_attributes,
                    &output.pedersen,
                );

                //commits.commit(hasher);
                hasher.add(commits.hash());
            }
            None => {
                return Err(error::Error::MissingProofs);
            }
        }

        let signature_share = output.request.sign_request.blind_sign(
            &self.coconut.params,
            &self.secret,
            //&output.request.public_attributes,
            &Vec::new(),
        );

        Ok(OutputSignature {
            index: self.index,
            signature_share,
        })
    }
}
