************************************
Generating the Zero-Knowledge Proofs
************************************

There are 3 stages in generating the sigma zero-knowledge proofs used in DarkWallet.

* **Commitment**
* **Challenge**
* **Response**

Each party involved in a transaction, both the one sending and the ones receiving tokens must generate zero-knowledge proofs.

The protocol has a complication in that the everybody must generate commitments and share them with the sender, who computes a single challenge based on all the values from the parties involved in the transaction.

Once the challenge step is computed, each party can finish generating their proofs and add these to the transaction.

After the pedersen step is completed, each party then calls this function:

::

    // Begin computing the proofs
    let output1_proof_commits = output1_secret.proof_commits();

For both the inputs and the outputs.

These commitment values are then collected together, and the challenge is computed:

::

    // Hash all the proof commits together to generate a single challenge.
    let mut hasher = HasherToScalar::new();
    input_proof_commits.commit(&mut hasher);
    output1_proof_commits.commit(&mut hasher);
    output2_proof_commits.commit(&mut hasher);
    let challenge = hasher.finish();

The challenge is then passed by the sender to everybody else involved in the transaction, and used to compute the responses.

::

    let output1_proofs = output1_secret.finish(&challenge);
    tx.outputs[output1_id].set_proof(output1_proofs);

Also do not forget to add the challenge to the transaction.

::

    tx.challenge = challenge;

Now the transaction is complete and ready for processing by the services!
