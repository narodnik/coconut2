***********************
Computing the Pedersens
***********************

After we have created the transaction, next we must compute the pedersens.

The person performing this step must know all the values in the transaction- the values of the tokens going in and going out. For this reason, usually the sender performs this step.

The code is very simple:

::

    let (input_blinds, output_blinds) = tx.compute_pedersens(
        &coconut,
        &vec![input_token_value],
        &vec![output_token1_value, output_token2_value],
    );

Here we have a pedersen computation for a transaction with 1 input and 2 outputs. If there are no inputs (like with a deposit) or no outputs (withdraw), then just use an empty vector.

The function returns 2 vectors containing the blinding values used for the pedersen commits. These blinding values must be passed to each party involved in the transaction.

They will then call the setup function on their token secret.

::

    input_secret.setup(input_blinds[input_id]);

And likewise for the outputs:

::

    output1_secret.setup(output_blinds[output1_id]);

Each person involved in the transaction has now setup their input and output secrets.

We are ready to go onto the final stage of generating the zero-knowledge proofs.
