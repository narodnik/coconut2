.. _tut-overview:

********
Overview
********

DarkWallet gives us basic anonymized transactions which can contain further anonymous attributes. This can be used for constructing a wide variety of financial applications.

Coconut Credentials
===================

Coconut is a cryptographic scheme created by Alberto Sonnino and others under the title `"Coconut: Threshold Issuance Selective Disclosure Credentials with Applications to Distributed Ledgers" <https://arxiv.org/pdf/1802.07344.pdf>`_. This system was partly inspired by earlier work on creating universal authentication mechanisms for websites. The authors of this paper wanted to find a method for creating anonymous authentication for websites using a single account.

Credentials are a kind of access token, like a website cookie which contains several values that are signed by a service (this is called a signing authority in Coconut terminology). When authenticating to an application, the application will check the attributes according to some rules defined by its logic, as well as making sure the signing service has authorized that attribute (by having signed that attribute).

David Chaum introduced the idea of the `blind signature <https://en.wikipedia.org/wiki/Blind_signature>`_ in 1983. Chaum's idea was to use a kind of credential containing a serial number as a non-divisible unit, called a Chaumian token. However to ensure its anonymity, instead of using normal signatures, he would use *blind signatures*. The token would be encrypted before being signed by the service, then unencrypted by the user. This means the token would have a property called *unlinkability*. Unlinkability means that the service would be unable to link the issuance of the credential with its later redeem (spend).

Coconut is an upgrade to Chaum's original scheme. It allows threshold issuance with M required signatures from N services such as 5 of 7. Credentials also contain multiple attributes which can be selectively revealed. This makes the system attractive for building decentralized cryptographic applications.

Here's a full list of Coconut's features:

* **Threshold authorities:** Only a subset of the authorities is required to issue partial credentials in order to allow the users to generate a complete credential. The communication complexity of the *request and issue* protocol is thus O(t), where t is the size of the subset of authorities. Furthermore, it is impossible to generate a complete credential from fewer than t partial credentials.

* **Blind issuance & Unlinkability:** The authorities issue the credential without learning any additional information about the anonymous attributes embedded in the credential. Furthermore, it is impossible to link multiple showings of the credentials with each other, or the issuing transcript, even if all the authorities collude.

* **Non-interactivity:** The authorities may operate independently of each other, following a simple key distribution and setup phase to agree on public security and cryptographic parameters - they do not need to synchronize or further coordinate their activities.

* **Liveness:** Coconut guarantees liveness as long as a threshold number of authorities remains honest and weak synchrony assumptions holds for the key distribution.

* **Efficiency:** The credentials and all zero-knowledge proofs involved in the protocols are short and computationally efficient. After aggregation and re-randomization, the attribute showing and verification involve only a single consolidated credential, and are therefore O(1) in terms of both cryptographic computations and communication of cryptographic material - no matter the number of authorities.

* **Short credentials:** Each partial credential - as well as the consolidated credential - is composed of exactly two group elements, no matter the number of authorities or the number of attributes embedded in the credentials.

Below we list the specification for the Coconut cryptographic scheme. At the start the signing services generate a secret key, then aggregate their public keys together to create a single verification key. This can be used to verify that at least M of N services signed the credential.

Then a user can send a message (credential with encrypted attribute) to the signing services by which they will issue the new credential by creating a valid signature for it.

Lastly when the user wishes to use the credential, they can then generate a proof which can be verified by other entities as being valid.

* :math:`\operatorname{\textbf{Setup}}(1^\lambda) \rightarrow (params):` defines  the  system  parameters :math:`params` with respect to the security parameter :math:`\lambda`. These parameters are publicly available.
* :math:`\operatorname{\textbf{KeyGen}}(params) \rightarrow (sk, vk):` is run by the authorities to generate their secret key :math:`sk` and verification key :math:`vk` from the public :math:`params`.
* :math:`\operatorname{\textbf{AggregateKey}}(vk_1, ..., vk_t) \rightarrow (vk):` is run by whoever wants to verify a credential to aggregate any subset of :math:`t` verification keys :math:`vk_i` into a single consolidated verification key :math:`vk`. :math:`\operatorname{AggregateKey}` needs to be run only once.
* :math:`\operatorname{\textbf{IssueCredential}}(m, \phi) \rightarrow (\sigma):` is an interactive protocol between a user and each authority, by which the user obtains a credential :math:`\sigma` embedding the private attribute :math:`m` satisfying the statement :math:`\phi`.
* :math:`\operatorname{\textbf{AggregateCredential}}(\sigma_1, ..., \sigma_t) \rightarrow (\sigma):` is run by the user to aggregate any subset of :math:`t` partial credentials :math:`\sigma_i` into a single consolidated credential.
* :math:`\operatorname{\textbf{ProveCredential}}(vk, m, \phi') \rightarrow (\Theta, \phi'):` is run by the user to compute a proof :math:`\Theta` of possession of a credential certifying that the private attribute :math:`m` satisfies the statement :math:`\phi'` (under the corresponding verification key :math:`vk`).
* :math:`\operatorname{\textbf{VerifyCredential}}(vk, \Theta, \phi') \rightarrow (true / false):` is run by whoever wants to verify a credential embedding a private attribute satisfying the statement :math:`\phi'`, using the verification key :math:`vk` and cryptographic material :math:`\Theta` generated by :math:`\operatorname{ProveCredential}`.

There are a wide variety of applications that can be built with Coconut, including as listed in the original paper a voting scheme and a coin tumbler. We will go further into potential applications later in this tutorial.

Confidential Transactions
=========================

Confidential transactions are a way of hiding transaction values through pedersen commitments. This means we can prove in a cryptographic transaction that the values being spent are the same as the values being sent, and no new money is created.

Normally to prove this we have to reveal the values in the transaction. Confidential transactions enable us to prove this without the actual values being visible. This is the second important part of our anonymity scheme, with the first being the breaking of transaction links.

Pedersen Commitments
--------------------

Under normal conditions, entity A could generate a random number, send it to B, and then B could generate a fake random number because they have knowledge of A's number. The solution to this is to use a commitment scheme.

One such commitment scheme is the hash function. B could generate a random number, and send the hash of that number to A. Then A sends their random number to B, with B now revealing the number that created the hash they sent to A. Because hash functions are irreversible, there is no way for A to guess the number that went into B until B actually shows them the number. And since B gave a hash to A of their number, they are now *committed* to the number they generated, and A will only accept the correct number that was generated by B without foreknowledge of A's number.

Another cryptographic commitment scheme is the Pedersen commitment scheme. The Pedersen commitment scheme is a way of *committing* to a value. This is neccessary for certain types of protocols where two separate entities must generate random numbers.

This scheme has other nice properties that make it an improvement on the hash-based scheme such as being able to be used inside zero-knowledge proofs. The formula for this scheme is:

.. math::

   C &= \operatorname{PedersenCommit}(v, b) \\
     &= vG + bH

Where :math:`G` and :math:`H` are elliptic curve generator points, :math:`v` is the value being committed and :math:`b` is a random blinding factor.

Without the term :math:`bH`, if :math:`v` is a small number then the commitment could be brute force attacked, allowing A to guess the number inside the commitment.

We mentioned above that Pedersen commitments have other nice cryptographic properties, distinct from the hash-based commitment scheme. One of these properties is what's called the *homomorphic* property. Homomorphism is defined as:

.. math::

   f(x \cdot y) = f(x) \cdot f(y)

For Pedersen commits, means that if these relations are true:

.. math::

   v &= v_1 + ... + v_n \\
   b &= b_1 + ... + b_n

Then this relation is also true:

.. math::

   \operatorname{PedersenCommit}(v, b) = \operatorname{PedersenCommit}(v_1, b_1) + ... + \operatorname{PedersenCommit}(v_n, b_n)

Using pederson commitments, it's impossible to find the value :math:`v` given its commitment :math:`C` (assuming :math:`b` is a large randomly chosen number). We therefore have a system to prove that the values of coins being burnt are the same as new ones being created, while keeping the amounts private.

This system is called **confidential transactions** and enables us to improve the Chaumian scheme. Whereas the Chaumian scheme represents amounts through N tokens (leaking the amount of coins being spent and minted in a transaction), this scheme enables us to hide this metadata.

Schnorr Zero-Knowledge Proofs
=============================

The last component we use are a variant of zero-knowledge proofs called schnorr sigma proofs. Zero-knowledge proofs enable us to make statements about variables without revealing their value. These statements can prove that values are constructed according to a set of rules that prove their validity.

For example, above we introduced the idea of a pedersen commitment. Our system will use a proof to say that the value encoded in the pedersen commitment is the same value stored in our credential.

There is a special way of writing proofs. The proof for our pedersen commitment would look like this:

.. math::

   \pi = \{(v, b): C = vG + bH\}

Here :math:`\pi` is the proof itself, and :math:`(v, b)` are the secret values we don't reveal. What we are saying here is that :math:`C` is constructed in such and such a way.

Now proofs can be combined. For example we also should prove that the value :math:`v` is contained inside the credential.

.. math::

   \pi = \{(v, b, o, s): C = vG + bH_1 \wedge c_m = oG_1 + vH_1 + sH_2\}

Don't worry about the formula here. Just know that the value :math:`c_m` represents the token. Here our proof says that the Pedersen commit :math:`C` is a commitment to the same value contained in the credential, and that the Pedersen commit is correctly formed.

The Sigma Protocol
------------------

There are 3 steps in generating the zero-knowledge proofs used in DarkWallet. This 3 step process is called a sigma protocol.

* **Commitment**
* **Challenge**
* **Response**

We provide the simplest proof here which is a proof that :math:`P = xG` or more formally:

.. math::

   \pi = \{(x): P = xG\}

The first round we generate a random secret, and commit to this value without revealing what is it. We call this the **commitment** stage.

.. math::

    \operatorname{random} k

    R = kG

Then we get given a random value from the counterparty we are generating the proof for. This is the **challenge** step.

Now instead of waiting for a random value everytime we want to make our proof, we can also use a trick using what is called a *one-way function*. We use a hash function as this since they cannot be reversed.

.. math::

    c = H(R)

Finally we create the **response**.

.. math::

    s = k + cx

The final signature is the values :math:`(c, s)`

To verify the proof, anybody can check it's valid by running these equations:

.. math::

    R &= sG - cP \\
    c &\stackrel{?}{=} H(R)

This is true because :math:`s = k + cx` and multiplying by :math:`G` gives us :math:`sG = kG + cxG`. Substituting in :math:`R = kG` and :math:`P = xG`, we get:

.. math::

   sG = R + cP

Rearranging to make :math:`R` the subject, we can then see if the proof is valid by seeing if hashing :math:`R` gives us the same challenge value :math:`c` that was provided by the proof.

This proof can only be generated if somebody possesses secret information for :math:`P = xG`. The one-way function ensures that the value :math:`k` is truly random.

Another fact to understand is that we cannot compute :math:`x` from :math:`s` because given an equation of the form:

.. math::

   A = Bx + y

Given A and B, it's impossible to find :math:`x` or :math:`y` without knowing at least one of them or another equation that we can substitute in. Also we use :math:`R` in place of :math:`k` but recall that :math:`R = kG`, and elliptic curve functions are irreversible- namely, given :math:`R` and :math:`G`, we cannot find :math:`k`.

