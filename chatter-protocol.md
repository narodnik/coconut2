% Transaction Protocol (On Blockchain)

# Overview

Constructing a ZK transaction requires several interactive steps between sender and receiver.

Below we detail simple first version protocol for a sender to receive funds.

# Packet

| Bytes     | Name           | Description            |
|-----------|----------------|------------------------|
| 1         | Command        | Enum of message type   |
| varuint   | Payload length | Length of payload data |
| ...       | Payload data   | Payload data           |

Packets are then deserialized into messages.

# Message

Command enumeration types:

| Command               | Value | Description                                               |
|-----------------------|-------|-----------------------------------------------------------|
| CREATE_OUTPUT         | 0     | Create an output to initiate receive funds                |
| OUTPUT                | 1     | Output for receiving funds                                |
| REQUEST_MINT_SIGN     | 2     | Request signature from signing services                   |
| MINT_SIGNATURE        | 3     | Finalized partial signature from a mint                   |

# Sending a transaction

## Stage 1: setup phase [Alice]

```rust
    // Compute pedersens from the transaction.
    // It's OK for wallet1 and wallet2 to share this info, but not with anybody else.
    let (deposits_blind, withdraws_blind, input_blinds, output_blinds) =
        df::compute_pedersen_blinds(
            &coconut,
            0,
            0,
            &vec![token_secret.value],
            &vec![token1_value, token2_value],
        );
```

## Stage 2: create a receiving output [Bob]

Alice sends Bob a **CREATE_OUTPUT** message.

```rust
    let output1_id = 0;

    let (mut output1, mut output1_secret) = df::Output::new(&coconut, &token1_secret);

    output1_secret.setup(output_blinds[output1_id]);
    let output1_proof_commits_hash = output1_secret.proof_commits().hash();

    let mut hasher = df::HasherToScalar::new();
    hasher.add(output1_proof_commits_hash);
    let challenge_output1 = hasher.finish();

    let output1_proofs = output1_secret.finish(&challenge_output1);

    output1.set_proof(output1_proofs);
    output1.challenge = Some(challenge_output1);
```

Data needed by Alice:

* `output1`
* `output1_proof_commits_hash`

Bob sends this data to Alice in an **OUTPUT** message.

## Stage 3: complete the tx [Alice]

Alice now finishes completing the tx with the inputs, proofs and so on.

## Stage 4: push to mint signing services

Make sure the challenge is set on the tx:

```rust
    // Also add challenge to transaction
    tx.challenge = challenge;
```

Execute tx signing with **REQUEST_MINT_SIGN** message.

Receive back partial signatures from the mints with the **MINT_SIGNATURE** message.

Unblind tokens received back using `token_secret` value and the partial signatures.

# Structures

## CREATE_OUTPUT         

Create an output to initiate receive funds.

| Size      | Name                      | Type                  | Description                            |
|-----------|---------------------------|-----------------------|----------------------------------------|
| 32        | payment_id                | [u8; 32]              | Payment ID                             |
| 8         | value                     | u64                   | Value of the output amount             |
| 32        | blind                     | bls::Scalar           | Pedersen blinding value                |
| 48        | reply_address             | df::StealthAddress    | Reply address for the output           |

## OUTPUT

Output for receiving funds.

| Size      | Name                      | Type            | Description                            |
|-----------|---------------------------|-----------------|----------------------------------------|
| 32        | payment_id                | [u8; 32]        | Payment ID                             |
| 1+        | output_length             | VarInt          | Length of output data                  |
| ?         | output                    | df::Output      | Output data                            |
| 32        | proof_commits_hash        | df::ProofHash   | Hash of output proof commit values     |

## REQUEST_MINT_SIGN  

Request signature from signing services.

| Bytes     | Name           | Description            |
|-----------|----------------|------------------------|
| 32        | Payment id     | Payment ID             |
| varuint   | Tx data length | Length of tx data      |
| ...       | Tx data        | Tx data                |

## MINT_SIGNATURE     

Finalized partial signature from a mint.

| Bytes     | Name              | Description            |
|-----------|-------------------|------------------------|
| 32        | Payment id        | Payment ID             |
| ...       | Partial signature | Partial signature data |

# Send protocol example

Alice has a coin worth 2 BTC, and wishes to send 0.5 BTC to Bob.

Alice sends **CREATE_OUTPUT** message to Bob.

Bob creates a new output.

Bob sends **OUTPUT** message to Alice.

Alice completes the tx.

Alice sends **REQUEST_MINT_SIGN** to the Mints.

The minds respond back with **MINT_SIGNATURE** to Alice.

