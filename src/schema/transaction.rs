use bls12_381 as bls;
use itertools::izip;
use std::io;

use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::error::Result;
use crate::pedersen::*;
use crate::schema::input::*;
use crate::schema::output::*;
use crate::schema::token::*;
use crate::serial::{Decodable, Encodable};
use crate::utility::*;

// deposits + inputs == withdraws + outputs
pub struct Transaction {
    // deposits - withdraws
    pub deposits: u64,
    deposits_blind: bls::Scalar,
    pub withdraws: u64,
    withdraws_blind: bls::Scalar,

    // burns
    pub inputs: Vec<Input>,
    // mints
    pub outputs: Vec<Output>,

    pub challenge: bls::Scalar,
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            deposits: 0,
            deposits_blind: bls::Scalar::zero(),
            withdraws: 0,
            withdraws_blind: bls::Scalar::zero(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            challenge: bls::Scalar::zero(),
        }
    }

    pub fn add_deposit(&mut self, value: u64) {
        self.deposits += value;
    }
    pub fn add_withdraw(&mut self, value: u64) {
        self.withdraws += value;
    }

    // Burn input
    pub fn add_input(&mut self, input: Input) -> usize {
        self.inputs.push(input);
        self.inputs.len() - 1
    }
    // Mint output
    pub fn add_output(&mut self, output: Output) -> usize {
        self.outputs.push(output);
        self.outputs.len() - 1
    }

    pub fn compute_pedersens<R: RngInstance>(
        &mut self,
        coconut: &Coconut<R>,
        input_values: &Vec<u64>,
        output_values: &Vec<u64>,
    ) -> (Vec<bls::Scalar>, Vec<bls::Scalar>) {
        assert_eq!(input_values.len(), self.inputs.len());
        assert_eq!(output_values.len(), self.outputs.len());
        let params = &coconut.params;
        assert!(params.hs.len() > 0);

        // deposits + sum(inputs) == withdraws + sum(outputs)

        if self.deposits > 0 {
            self.deposits_blind = params.random_scalar();
        }
        if self.withdraws > 0 {
            self.withdraws_blind = params.random_scalar();
        }

        let mut input_blinds = Vec::with_capacity(self.inputs.len());
        let mut output_blinds = Vec::with_capacity(self.outputs.len());

        for _ in &self.inputs {
            input_blinds.push(params.random_scalar());
        }
        for _ in &self.outputs {
            output_blinds.push(params.random_scalar());
        }

        if !input_values.is_empty() {
            // rhs = withdraws + sum(outputs)
            let rhs = self.withdraws_blind + sum_scalar(output_blinds.iter());
            // lhs = deposits + sum(inputs[1:])
            let lhs = self.deposits_blind + sum_scalar(input_blinds.iter().skip(1));

            // inputs[0] = rhs - lhs
            input_blinds[0] = rhs - lhs;
        } else if !output_values.is_empty() {
            assert!(input_values.is_empty());

            // rhs = withdraws + sum(outputs[1:]
            let rhs = self.withdraws_blind + sum_scalar(output_blinds.iter().skip(1));

            // outputs[0] = deposits - rhs
            output_blinds[0] = self.deposits_blind - rhs;
        } else {
            assert!(input_values.is_empty());
            assert!(output_values.is_empty());

            // A nonsensical transaction
            // Maybe this should be disallowed.
            assert!(self.deposits == self.withdraws);
            self.deposits_blind = self.withdraws_blind;
        }

        // Test both sides are equal
        assert_eq!(
            self.deposits_blind + sum_scalar(input_blinds.iter()),
            self.withdraws_blind + sum_scalar(output_blinds.iter())
        );

        // Now set the pedersen commits

        for (input, value, blind) in izip!(&mut self.inputs, input_values, &input_blinds) {
            input.pedersen = compute_pedersen_with_u64(params, blind, *value);
        }
        for (output, value, blind) in izip!(&mut self.outputs, output_values, &output_blinds) {
            output.pedersen = compute_pedersen_with_u64(params, blind, *value);
        }

        // TODO: DOESNT WORK!!!! WTF
        //let lhs: bls::G1Projective = compute_pedersen(params, self.deposits, &self.deposits_blind)
        //    + self.inputs.iter().map(|input| input.pedersen).sum();
        assert!(self.check(coconut));

        (input_blinds, output_blinds)
    }

    pub fn set_blinds<R: RngInstance>(
        &mut self,
        coconut: &Coconut<R>,
        deposits_blind: bls::Scalar,
        withdraws_blind: bls::Scalar,
        input_blinds: &Vec<bls::Scalar>,
        input_values: &Vec<u64>,
        output_blinds: &Vec<bls::Scalar>,
        output_values: &Vec<u64>,
    ) {
        assert_eq!(input_values.len(), self.inputs.len());
        assert_eq!(output_values.len(), self.outputs.len());
        let params = &coconut.params;
        assert!(params.hs.len() > 0);

        self.deposits_blind = deposits_blind;
        self.withdraws_blind = withdraws_blind;

        for (input, value, blind) in izip!(&mut self.inputs, input_values, input_blinds) {
            input.pedersen = compute_pedersen_with_u64(params, blind, *value);
        }
        for (output, value, blind) in izip!(&mut self.outputs, output_values, output_blinds) {
            output.pedersen = compute_pedersen_with_u64(params, blind, *value);
        }
    }

    pub fn check<R: RngInstance>(&self, coconut: &Coconut<R>) -> bool {
        let params = &coconut.params;
        assert!(params.hs.len() > 0);

        let mut lhs = compute_pedersen_with_u64(params, &self.deposits_blind, self.deposits);
        for input in &self.inputs {
            lhs += input.pedersen;
        }

        let mut rhs = compute_pedersen_with_u64(params, &self.withdraws_blind, self.withdraws);
        for output in &self.outputs {
            rhs += output.pedersen;
        }

        lhs == rhs
    }

    pub fn unblind<R: RngInstance>(
        &self,
        coconut: &Coconut<R>,
        token_secrets: &Vec<&TokenSecret>,
        output_signatures: Vec<Vec<OutputSignature>>,
    ) -> Vec<Token> {
        // output_signatures.len() == number of authorities
        // output_signatures[i].len() == self.outputs.len()
        let output_signatures = transpose(output_signatures);
        assert_eq!(output_signatures.len(), self.outputs.len());
        assert_eq!(token_secrets.len(), self.outputs.len());

        let mut tokens = Vec::with_capacity(self.outputs.len());

        for (output, token_secret, partial_signatures) in
            izip!(&self.outputs, token_secrets, output_signatures)
        {
            tokens.push(output.unblind(coconut, token_secret, partial_signatures));
        }

        tokens
    }
}

impl Encodable for Transaction {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.deposits.encode(&mut s)?;
        len += self.deposits_blind.encode(&mut s)?;
        len += self.withdraws.encode(&mut s)?;
        len += self.withdraws_blind.encode(&mut s)?;
        len += self.inputs.encode(&mut s)?;
        len += self.outputs.encode(&mut s)?;
        Ok(len + self.challenge.encode(s)?)
    }
}

impl Decodable for Transaction {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            deposits: Decodable::decode(&mut d)?,
            deposits_blind: Decodable::decode(&mut d)?,
            withdraws: Decodable::decode(&mut d)?,
            withdraws_blind: Decodable::decode(&mut d)?,
            inputs: Decodable::decode(&mut d)?,
            outputs: Decodable::decode(&mut d)?,
            challenge: Decodable::decode(d)?,
        })
    }
}
