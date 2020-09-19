#[allow(unused_imports)]
use crate::bls_extensions::*;
#[allow(unused_imports)]
use crate::coconut::coconut::*;
#[allow(unused_imports)]
use crate::pedersen::*;
#[allow(unused_imports)]
use crate::proofs::proof::*;
#[allow(unused_imports)]
use crate::schema::input::*;
#[allow(unused_imports)]
use crate::schema::output::*;
#[allow(unused_imports)]
use crate::schema::service::*;
#[allow(unused_imports)]
use crate::schema::token::*;
#[allow(unused_imports)]
use crate::schema::transaction::*;

#[test]
fn test_schema_asset() {
    //
    // Initialization
    //

    let number_attributes = 2;
    let threshold_service = 5;
    let total_services = 5;

    let (secret_keys, verify_key) =
        generate_keys(number_attributes, threshold_service, total_services);
    let coconut =
        Coconut::<OsRngInstance>::new(number_attributes, threshold_service, total_services);

    // Create our services that will sign new credentials
    let mut services: Vec<_> = secret_keys
        .into_iter()
        .enumerate()
        .map(|(index, secret)| {
            SigningService::from_secret(&coconut, secret, verify_key.clone(), (index + 1) as u64)
        })
        .collect();

    //
    // Deposit
    //

    // wallet: Deposit a new token worth 110 credits
    let token_value = 110;
    let token_secret = TokenSecret::generate(token_value, &coconut);

    println!("Deposit started...");

    let token = {
        // wallet: Create a new transaction
        let mut tx = Transaction::new();
        // wallet: Create a single output
        let (output, mut output_secret) = Output::new(&coconut, &token_secret);

        // wallet: We are depositing 110, so expect a new token of 110 to be minted
        tx.add_deposit(token_secret.value);
        let output_id = tx.add_output(output);

        // Once we have added the inputs and outputs, we must call this function...
        let (_input_blinds, output_blinds) =
            tx.compute_pedersens(&coconut, &vec![], &vec![token_value]);

        // wallet: Then for every input/output we created, call this one.
        output_secret.setup(output_blinds[output_id]);
        // wallet: Now start to generate the proofs
        let output_proof_commits = output_secret.proof_commits();

        let mut hasher = HasherToScalar::new();
        //output_proof_commits.commit(&mut hasher);
        hasher.add(output_proof_commits.hash());
        let challenge = hasher.finish();

        std::mem::drop(output_proof_commits);

        // wallet: Finish proof and add it to our transaction
        let output_proofs = output_secret.finish(&challenge);
        tx.outputs[output_id].set_proof(output_proofs);
        tx.outputs[output_id].challenge = Some(challenge);

        // Also set the challenge computed from all the proofs in our transaction
        tx.challenge = challenge;

        // service: Each service will now validate and sign the transaction
        let output_signatures: Vec<_> = services
            .iter_mut()
            .map(|service| match service.process(&tx) {
                Ok(signatures) => {
                    println!(
                        "Service-{} signed {} tokens",
                        service.index,
                        signatures.len()
                    );
                    signatures
                }
                Err(err) => {
                    panic!("Error occured signing (service={}): {}", service.index, err);
                }
            })
            .collect();

        // wallet: Unblind and accept the returned signed token if signed by at least
        //         M of N services.
        let mut tokens = tx.unblind(&coconut, &vec![&token_secret], output_signatures);
        assert!(tokens.len() == 1);
        tokens.pop().unwrap()
    };

    println!("Deposit finished.");

    //
    // Split
    //
    // wallet1: We will now split our deposited token into 2 new tokens...
    let (token1_value, token2_value) = (100, 10);
    let token1_secret = TokenSecret::generate(token1_value, &coconut);
    // wallet2: This is my token
    let token2_secret = TokenSecret::generate(token2_value, &coconut);

    println!("Split started...");

    let split_tokens = {
        /////////////////////////////////////////////
        // Alice
        /////////////////////////////////////////////

        // Compute pedersens from the transaction.
        // It's OK for wallet1 and wallet2 to share this info, but not with anybody else.
        let (deposits_blind, withdraws_blind, input_blinds, output_blinds) =
            compute_pedersen_blinds(
                &coconut,
                0,
                0,
                &vec![token_secret.value],
                &vec![token1_value, token2_value],
            );

        /////////////////////////////////////////////
        // Bob
        /////////////////////////////////////////////

        let output1_id = 0;

        let (mut output1, mut output1_secret) = Output::new(&coconut, &token1_secret);

        output1_secret.setup(output_blinds[output1_id]);
        let output1_proof_commitish = output1_secret.proof_commits().hash();

        let mut hasher = HasherToScalar::new();
        hasher.add(output1_proof_commitish);
        let challenge_output1 = hasher.finish();

        let output1_proofs = output1_secret.finish(&challenge_output1);

        output1.set_proof(output1_proofs);
        output1.challenge = Some(challenge_output1);

        // Data needed by Alice:
        // * output1
        // * output1_proof_commitish

        /////////////////////////////////////////////
        // Alice
        /////////////////////////////////////////////

        // New transaction as before
        let mut tx = Transaction::new();
        // wallet1: Create input and output
        let (input, mut input_secret) =
            Input::new(&coconut, &verify_key, &token, &token_secret);
        // wallet2: Also create another output
        let (output2, mut output2_secret) = Output::new(&coconut, &token2_secret);

        // We are splitting token of 110 into two new tokens of 100 and 10
        let input_id = tx.add_input(input);
        let output1_id_check = tx.add_output(output1);
        assert_eq!(output1_id, output1_id_check);
        let output2_id = tx.add_output(output2);

        println!("  created transaction");

        tx.set_blinds(
            &coconut,
            deposits_blind,
            withdraws_blind,
            &input_blinds,
            &vec![token_secret.value],
            &output_blinds,
            &vec![token1_value, token2_value],
        );

        println!("  computed pedersens");

        assert_eq!(input_id, 0);
        assert_eq!(input_blinds.len(), 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(input_secret.value, token_secret.value);
        assert_eq!(
            tx.inputs[input_id].pedersen,
            compute_pedersen_with_u64(
                &coconut.params,
                &input_blinds[input_id],
                input_secret.value
            )
        );
        // Debug
        //println!("main(): input.pedersen = {:?}", tx.inputs[input_id].pedersen);
        //println!("main(): blind = {:?}", input_blinds[input_id]);
        //println!("main(): value = {:?}", bls::Scalar::from(input_secret.value));

        // wallet1: Now pass this info to our input_secret
        input_secret.setup(input_blinds[input_id]);
        let input_proof_commits = input_secret.proof_commits();

        assert_eq!(output1_id, 0);
        assert_eq!(output2_id, 1);
        assert_eq!(output_blinds.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        //assert_eq!(output1_secret.value, token1_secret.value);
        assert_eq!(output2_secret.value, token2_secret.value);
        /*
        assert_eq!(
            tx.outputs[output1_id].pedersen,
            compute_pedersen_with_u64(
                &coconut.params,
                &output_blinds[output1_id],
                output1_secret.value
            )
        );
        */
        assert_eq!(
            tx.outputs[output2_id].pedersen,
            compute_pedersen_with_u64(
                &coconut.params,
                &output_blinds[output2_id],
                output2_secret.value
            )
        );

        // wallet1 and wallet2: also do the same for the outputs
        output2_secret.setup(output_blinds[output2_id]);
        // Begin computing the proofs
        let output2_proof_commits = output2_secret.proof_commits();

        // Hash all the proof commits together to generate a single challenge.
        let mut hasher = HasherToScalar::new();
        //input_proof_commits.commit(&mut hasher);
        //output1_proof_commits.commit(&mut hasher);
        //output2_proof_commits.commit(&mut hasher);
        hasher.add(input_proof_commits.hash());
        hasher.add(output1_proof_commitish);
        hasher.add(output2_proof_commits.hash());
        let challenge = hasher.finish();

        let mut hasher = HasherToScalar::new();
        hasher.add(output2_proof_commits.hash());
        let challenge_output2 = hasher.finish();

        std::mem::drop(input_proof_commits);
        //std::mem::drop(output1_proof_commits);
        std::mem::drop(output2_proof_commits);

        // wallet1: Add finished proofs to transaction
        let input_proofs = input_secret.finish(&challenge);
        tx.inputs[input_id].set_proof(input_proofs);

        // wallet2: Also add finished proof to transaction
        let output2_proofs = output2_secret.finish(&challenge_output2);
        tx.outputs[output2_id].set_proof(output2_proofs);
        tx.outputs[output2_id].challenge = Some(challenge_output2);

        // Also add challenge to transaction
        tx.challenge = challenge;

        println!("  generated proofs");

        // service: If the transaction is valid then sign it
        let output_signatures: Vec<_> = services
            .iter_mut()
            .map(|service| match service.process(&tx) {
                Ok(signatures) => {
                    println!(
                        "Service-{} signed {} tokens",
                        service.index,
                        signatures.len()
                    );
                    signatures
                }
                Err(err) => {
                    panic!("Error occured signing (service={}): {}", service.index, err);
                }
            })
            .collect();

        // Valid output tokens returned from services
        // wallet1 and wallet2: Unblind the tokens
        let tokens = tx.unblind(
            &coconut,
            &vec![&token1_secret, &token2_secret],
            output_signatures,
        );
        println!("  unblinded {} signed tokens", tokens.len());

        assert!(tokens.len() == 2);
        tokens
    };
    let (_token1, token2) = (&split_tokens[0], &split_tokens[1]);

    //
    // Withdraw
    //
    {
        // This is mostly the same as the deposit stage but in reverse.
        // We add an input representing the coin going out ...
        // ... and add a withdrawal representing the money leaving the system.
        let mut tx = Transaction::new();
        let (input, mut input_secret) =
            Input::new(&coconut, &verify_key, &token2, &token2_secret);

        // We are wihdrawing a single token
        tx.add_withdraw(token2_secret.value);
        let input_id = tx.add_input(input);

        // As before compute the pedersens...
        let (input_blinds, _) = tx.compute_pedersens(&coconut, &vec![token2_secret.value], &vec![]);

        assert_eq!(input_id, 0);
        assert_eq!(input_blinds.len(), 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(input_secret.value, token2_secret.value);
        assert_eq!(
            tx.inputs[input_id].pedersen,
            compute_pedersen_with_u64(
                &coconut.params,
                &input_blinds[input_id],
                input_secret.value
            )
        );
        // ... then compute the proofs
        input_secret.setup(input_blinds[input_id]);
        let input_proof_commits = input_secret.proof_commits();

        let mut hasher = HasherToScalar::new();
        hasher.add(input_proof_commits.hash());
        let challenge = hasher.finish();

        std::mem::drop(input_proof_commits);

        // And add the finished proof to the transaction
        let input_proofs = input_secret.finish(&challenge);
        tx.inputs[input_id].set_proof(input_proofs);
        // As well as the challenge
        tx.challenge = challenge;

        // We don't create any tokens. The service either accepts or denies the tx.
        for service in &mut services {
            match service.process(&tx) {
                Ok(_) => {
                    println!("Service-{} approved the withdrawal", service.index);
                }
                Err(err) => {
                    panic!("Error occured signing (service={}): {}", service.index, err);
                }
            }
        }
    }
}
