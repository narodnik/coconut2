****************
Signing Services
****************

Here we create 7 signing services, with a required number of 5 signatures as our threshold. Our credentials have 2 attributes (the serial number and value).

::

    let number_attributes = 2;
    let threshold_service = 5;
    let total_services = 5;

    let (secret_keys, verify_key) =
        generate_keys(number_attributes, threshold_service, total_services);
    let coconut =
        Coconut::<OsRngInstance>::new(number_attributes, threshold_service, total_services);

These secret keys are passed amongst the individual servers.

To instantiate a signing service, call:

::

    SigningService::from_secret(&coconut, secret, verify_key.clone(), (index + 1) as u64)

Note the :code:`(index + 1)` part. Service indexes begin from 1 until N (so 1, 2, ..., 7 in our example).

Processing Transactions
=======================

Simply call the :code:`process()` function.

::

    let signatures = match service.process(&tx) {
        Ok(signatures) => {
            println!("Service-{} signed {} tokens", service.index, signatures.len());
            signatures
        }
        Err(err) => {
            panic!("Error occured signing (service={}): {}", service.index, err);
        }
    }

In a production server you probably don't want to panic, and want to handle the error properly.

Assuming the transaction is valid, it will return a group of *partial* signatures. We need at least M valid partial transactions in our M-of-N scheme, to construct a fully valid complete signature for our tokens.

Synchronizing Spent Serial Codes
================================

When a token is spent, it reveals a special serial code which prevents double spending. It's important that services keep their list of serial codes synchronized amongst each other.

This is stored as the :code:`spent` field in the :code:`SigningService` struct (see below).

::

    type SpentBurns = Vec<bls::G1Projective>;

    pub struct SigningService {
        // ...
        spent: SpentBurns,
    }

