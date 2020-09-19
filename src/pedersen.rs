use bls12_381 as bls;

use crate::bls_extensions::*;
use crate::coconut::Coconut;
use crate::parameters::*;

pub type PedersenCommit = bls::G1Projective;

pub fn compute_pedersen<R: RngInstance>(
    params: &Parameters<R>,
    blind: &bls::Scalar,
    value: &bls::Scalar,
) -> PedersenCommit {
    assert!(params.hs.len() > 0);
    params.g1 * blind + params.hs[0] * value
}

pub fn compute_pedersen_with_u64<R: RngInstance>(
    params: &Parameters<R>,
    blind: &bls::Scalar,
    value: u64,
) -> PedersenCommit {
    assert!(params.hs.len() > 0);
    let value = bls::Scalar::from(value);
    compute_pedersen(params, blind, &value)
}

pub fn compute_pedersen_blinds<R: RngInstance>(
    coconut: &Coconut<R>,
    deposits: u64,
    withdraws: u64,
    input_values: &Vec<u64>,
    output_values: &Vec<u64>,
) -> (bls::Scalar, bls::Scalar, Vec<bls::Scalar>, Vec<bls::Scalar>) {
    let params = &coconut.params;
    assert!(params.hs.len() > 0);

    // deposits + sum(inputs) == withdraws + sum(outputs)

    let deposits_blind = if deposits > 0 {
        params.random_scalar()
    } else {
        bls::Scalar::zero()
    };

    let withdraws_blind = if withdraws > 0 {
        params.random_scalar()
    } else {
        bls::Scalar::zero()
    };

    let mut input_blinds = params.random_scalars(input_values.len());
    let mut output_blinds = params.random_scalars(output_values.len());

    // Transaction must have either an input or output
    // Otherwise it's nonsense
    assert!(!input_values.is_empty() && !output_values.is_empty());

    if !input_values.is_empty() {
        // Transaction has >=1 inputs and any number of outputs
        assert!(!output_values.is_empty() || withdraws > 0);

        // rhs = withdraws + sum(outputs)
        let rhs = withdraws_blind + sum_scalar(output_blinds.iter());
        // lhs = deposits + sum(inputs[1:])
        let lhs = deposits_blind + sum_scalar(input_blinds.iter().skip(1));

        // inputs[0] = rhs - lhs
        input_blinds[0] = rhs - lhs;
    } else if !output_values.is_empty() {
        // Transaction has no inputs but >= 1 outputs
        assert!(input_values.is_empty());

        // rhs = withdraws + sum(outputs[1:]
        let rhs = withdraws_blind + sum_scalar(output_blinds.iter().skip(1));

        // outputs[0] = deposits - rhs
        output_blinds[0] = deposits_blind - rhs;
    }

    // Test both sides are equal
    assert_eq!(
        deposits_blind + sum_scalar(input_blinds.iter()),
        withdraws_blind + sum_scalar(output_blinds.iter())
    );

    (deposits_blind, withdraws_blind, input_blinds, output_blinds)
}
