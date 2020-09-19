**********************
Creating a Transaction
**********************

Theory
======

Transactions have 4 components:

* **Deposits**. When we create new tokens, this plaintext field must be set to the total value of new tokens being created. We must also create the relevant outputs.
* **Withdraws**. This field is concerned with tokens being burned. The tokens burned are set in the input.
* **Inputs**. Tokens going into the transaction that will be destroyed.
* **Outputs**. New tokens that will be minted.

Importantly, the money going in must equal the money going out:

.. math::

   \sum{\operatorname{inputs}} + \sum{\operatorname{deposits}}
   =
   \sum{\operatorname{outputs}} + \sum{\operatorname{withdraws}}

This is ensured through zero-knowledge proofs.

Examples
--------

Deposit 100 BTC, send 10 BTC to user A, the rest to ourselves:

::

    Deposits: 100 BTC
    Outputs:
    - 10 BTC token
    - 90 BTC token

Burn a token worth 50 BTC, creating one token worth 5 BTC sending to user A (split operation):

::

    Inputs:
    - 50 BTC token
    Outputs:
    -  5 BTC token
    - 45 BTC token

Withdraw 2 tokens worth 10 BTC and 4 BTC:

::

    Inputs:
    - 10 BTC token
    -  4 BTC token
    Withdraws: 14 BTC

Deposit a Token
===============

First create the token secret.

::

    let token_value = 110;
    let token_secret = TokenSecret::generate(token_value, &coconut);

Create a new transaction.

::

    let mut tx = Transaction::new();

Create a single output.

::

    let (output, mut output_secret) = Output::new(&coconut, &token_secret);

We are depositing 110, so expect a new token of 110 to be minted.

::

    tx.add_deposit(token_secret.value);
    let output_id = tx.add_output(output);

Sending Payments
================

Construct a new transaction.

::

    let mut tx = Transaction::new();

Create the inputs and outputs.

::

    let (input, mut input_secret) = Input::new(&coconut, &verify_key, &token, &token_secret);
    let (output1, mut output1_secret) = Output::new(&coconut, &token1_secret);
    let (output2, mut output2_secret) = Output::new(&coconut, &token2_secret);

Add them to the transaction.

::

    let input_id = tx.add_input(input);
    let output1_id = tx.add_output(output1);
    let output2_id = tx.add_output(output2);

Here we create the 2 outputs in the same code, but we can imagine this being coordinated among 2 different users each with their own output and token secrets being kept private.

This makes splitting a token the same as a send operation.

Withdraw a Token
================

This is mostly the same as the deposit stage but in reverse. We add an input representing the coin going out and add a withdrawal representing the money leaving the system.

::

    let mut tx = Transaction::new();
    let (input, mut input_secret) = Input::new(&coconut, &verify_key, &token, &token_secret);

    // We are wihdrawing a single token
    tx.add_withdraw(token_secret.value);

