*****************
Unblinding Tokens
*****************

In the last step we processed our completed transaction and at least M out of N of our signing services returned valid signatures.

The last stage to receive our new tokens is to unblind them.

::

    let tokens = tx.unblind(
        &coconut,
        &vec![&token1_secret, &token2_secret],
        output_signatures,
    );

Now the tokens are fully constructed.

