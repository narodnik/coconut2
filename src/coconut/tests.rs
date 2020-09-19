#[allow(unused_imports)]
use bls12_381 as bls;
#[allow(unused_imports)]
use itertools::{chain, izip};
#[allow(unused_imports)]
use std::rc::Rc;

#[allow(unused_imports)]
use crate::bls_extensions::*;
#[allow(unused_imports)]
use crate::coconut::coconut::*;
#[allow(unused_imports)]
use crate::elgamal::*;
#[allow(unused_imports)]
use crate::proofs::credential_proof;
#[allow(unused_imports)]
use crate::proofs::proof::*;
#[allow(unused_imports)]
use crate::proofs::signature_proof;
#[allow(unused_imports)]
use crate::utility::*;

#[test]
fn test_multiparty_keygen() {
    let attributes_size = 2;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let sigs_x: Vec<bls::G1Projective> = secret_keys
        .iter()
        .map(|secret_key| coconut.params.g1 * secret_key.x)
        .collect();
    let l = lagrange_basis_from_range(6);

    let mut sig = bls::G1Projective::identity();
    for (s_i, l_i) in izip!(&sigs_x, &l) {
        sig += s_i * l_i;
    }

    let ppair_1 = bls::pairing(&bls::G1Affine::from(sig), &coconut.params.g2);
    let ppair_2 = bls::pairing(&coconut.params.g1, &bls::G2Affine::from(verify_key.alpha));
    assert_eq!(ppair_1, ppair_2);
}

#[test]
fn test_multiparty_coconut() {
    let attributes_size = 3;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let d = ElGamalPrivateKey::new(&coconut.params);
    let gamma = d.to_public(&coconut.params);

    let attribute_a = Attribute::new(bls::Scalar::from(110), 0);
    let attribute_b = Attribute::new(bls::Scalar::from(4), 1);
    let attribute_c = Attribute::new(bls::Scalar::from(256), 2);

    let private_attributes = vec![attribute_c, attribute_b];
    let public_attributes = vec![attribute_a];
    //let private_attributes = vec![bls::Scalar::from(110), bls::Scalar::from(4)];
    //let public_attributes = vec![bls::Scalar::from(256)];

    let (sign_request, sign_proof_values) =
        coconut.make_blind_sign_request(&gamma, &private_attributes, &public_attributes);

    let witness_blind = Rc::new(Witness::new(
        &coconut.params,
        sign_proof_values.blinding_factor.clone(),
    ));
    let witness_attributes: Vec<_> = chain(&private_attributes, &public_attributes)
        .map(|attribute| Rc::new(Witness::new(&coconut.params, attribute.value.clone())))
        .collect();
    let witness_keys: Vec<_> = sign_proof_values
        .attribute_keys
        .iter()
        .map(|key| Rc::new(Witness::new(&coconut.params, key.clone())))
        .collect();
    let attribute_indexes: Vec<_> = chain(&private_attributes, &public_attributes)
        .map(|attribute| attribute.index)
        .collect();

    let sign_proof_builder = signature_proof::Builder::new(
        &coconut.params,
        witness_blind.clone(),
        witness_attributes.clone(),
        witness_keys.clone(),
        attribute_indexes.clone(),
    );

    let sign_commitments = sign_proof_builder.commitments(
        &gamma,
        &sign_proof_values.commitish,
        &sign_request.attribute_commit,
    );

    let mut sign_hasher = HasherToScalar::new();
    sign_commitments.commit(&mut sign_hasher);
    let sign_challenge = sign_hasher.finish();

    // s = k + c x
    let response_blind = witness_blind.derive(&sign_challenge);
    let response_attributes = witness_attributes
        .iter()
        .map(|witness| witness.derive(&sign_challenge))
        .collect();
    let response_keys = witness_keys
        .iter()
        .map(|witness| witness.derive(&sign_challenge))
        .collect();
    let sign_proof = signature_proof::Proof {
        response_blind,
        response_attributes,
        response_keys,
    };

    let blind_signatures: Vec<_> = secret_keys
        .iter()
        .map(|secret_key| {
            let commitish = sign_request.compute_commitish();
            let commits = sign_proof.commitments(
                &coconut.params,
                &sign_challenge,
                &gamma,
                &commitish,
                &sign_request.attribute_commit,
                &sign_request.encrypted_attributes,
                &attribute_indexes,
            );
            let mut hasher = HasherToScalar::new();
            commits.commit(&mut hasher);
            let challenge = hasher.finish();

            assert_eq!(challenge, sign_challenge);

            sign_request.blind_sign(&coconut.params, secret_key, &public_attributes)
        })
        .collect();

    // Signatures should be a struct, with an authority ID inside them
    let mut signature_shares: Vec<_> = blind_signatures
        .iter()
        .map(|blind_signature| blind_signature.unblind(&d))
        .collect();
    let mut indexes: Vec<u64> = (1u64..=signature_shares.len() as u64).collect();

    signature_shares.remove(0);
    indexes.remove(0);
    signature_shares.remove(4);
    indexes.remove(4);

    let commitish = sign_request.compute_commitish();
    let signature = Signature {
        commitish,
        sigma: coconut.aggregate(&signature_shares, indexes),
    };

    let attribute_a = Attribute::new(bls::Scalar::from(110), 0);
    let attribute_b = Attribute::new(bls::Scalar::from(4), 1);
    let attribute_c = Attribute::new(bls::Scalar::from(256), 2);

    let private_attributes2 = vec![attribute_a, attribute_c];
    let public_attributes2 = vec![attribute_b];

    let (credential, credential_proof_values) =
        coconut.make_credential(&verify_key, &signature, &private_attributes2);

    let attribute_indexes: Vec<_> = private_attributes2
        .iter()
        .map(|attribute| attribute.index)
        .collect();
    let witness_attributes2: Vec<_> = private_attributes2
        .into_iter()
        .map(|attribute| Rc::new(Witness::new(&coconut.params, attribute.value)))
        .collect();
    let witness_blind = Rc::new(Witness::new(&coconut.params, credential_proof_values.blind));

    let credential_proof_builder = credential_proof::Builder::new(
        &coconut.params,
        witness_attributes2.clone(),
        witness_blind.clone(),
        attribute_indexes.clone(),
    );

    // Commits
    let credential_commitments =
        credential_proof_builder.commitments(&verify_key, &credential.blind_commitish);

    let mut hasher = HasherToScalar::new();
    credential_commitments.commit(&mut hasher);
    let challenge = hasher.finish();

    //Responses
    let response_attributes = witness_attributes2
        .iter()
        .map(|witness| witness.derive(&challenge))
        .collect();
    let response_blind = witness_blind.derive(&challenge);
    let credential_proof = credential_proof::Proof {
        response_attributes,
        response_blind,
    };

    let is_verify = credential.verify(&coconut.params, &verify_key, &public_attributes2);
    assert!(is_verify);

    let credential_verify_commitments = credential_proof.commitments(
        &coconut.params,
        &challenge,
        &verify_key,
        &credential.blind_commitish,
        &credential.kappa,
        &credential.v,
        &attribute_indexes,
    );

    let mut verify_hasher = HasherToScalar::new();
    credential_verify_commitments.commit(&mut verify_hasher);
    let verify_challenge = verify_hasher.finish();
    assert_eq!(verify_challenge, challenge);
}
