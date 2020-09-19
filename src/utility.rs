use bls12_381 as bls;
use std::borrow::Borrow;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hashable::*;

pub fn compute_polynomial<'a, I>(coefficients: I, x_primitive: u64) -> bls::Scalar
where
    I: Iterator<Item = &'a bls::Scalar>,
{
    let x = bls::Scalar::from(x_primitive);
    coefficients
        .enumerate()
        .map(|(i, coefficient)| coefficient * x.pow(&[i as u64, 0, 0, 0]))
        .fold(bls::Scalar::zero(), |result, x| result + x)
}

pub fn lagrange_basis<I>(indexes: I) -> Vec<bls::Scalar>
where
    I: Iterator + Clone,
    I::Item: Borrow<u64>,
{
    let x = bls::Scalar::zero();
    let mut lagrange_result = Vec::new();

    for i_value in indexes.clone() {
        let mut numerator = bls::Scalar::one();
        let mut denominator = bls::Scalar::one();

        let i_integer = *i_value.borrow();
        let i = bls::Scalar::from(i_integer);

        for j_value in indexes.clone() {
            let j_integer = *j_value.borrow();

            if j_integer == i_integer {
                continue;
            }

            let j = bls::Scalar::from(j_integer);
            numerator = numerator * (x - j);
            denominator = denominator * (i - j);
        }

        let result = numerator * denominator.invert().unwrap();
        lagrange_result.push(result);
    }

    lagrange_result
}

pub fn lagrange_basis_from_range(range_len: u64) -> Vec<bls::Scalar> {
    lagrange_basis(1..=range_len)
}

// TODO: This should just be hash to point
pub fn compute_commitish(attribute_commit: &bls::G1Projective) -> bls::G1Projective {
    let commit_data = bls::G1Affine::from(attribute_commit).to_compressed();
    let commitish = bls::G1Projective::hash_to_point(&commit_data);
    commitish
}

pub fn transpose<T>(mut input: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(input.len() > 0);

    for row in &mut input {
        row.reverse();
    }

    let mut result = Vec::with_capacity(input[0].len());
    while !input[0].is_empty() {
        let mut result_row = Vec::with_capacity(input.len());
        for input_row in &mut input {
            let value = input_row.pop();
            assert!(value.is_some());
            result_row.push(value.unwrap());
        }
        result.push(result_row);
    }

    result
}

pub fn get_current_time() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Incorrect system clock: time went backwards");
    let in_ms =
        since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_nanos() as u64 / 1_000_000;
    return in_ms;
}

#[test]
fn test_transpose() {
    let x = vec![vec![1, 2, 3], vec![4, 5, 6]];
    let tx = transpose(x);
    assert_eq!(tx, vec![vec![1, 4], vec![2, 5], vec![3, 6]]);
}
