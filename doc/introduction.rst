.. _tut-intro:

***************
Introduction
***************

DarkWallet is a crypto library targeted towards the creation of dark currency products. The library is modelled around the concept of the credential. Credentials can be used to access services, prove permissions or operate on currency.

Another core design principle is DarkWallet is not a framework, but a toolkit.  Frameworks hinder development during the latter stages of a development cycle, enforce one style of coding and do not work well with other frameworks.

Glossary
========

* **Credential**. The digital equivalent of a paper based passport, license, certificate or ticket which grants you access or permission to use a service. Credentials have ownership and prove statements contained inside them.
* **Threshold**. In cryptography, this has a special meaning for group digital signatures. We say a scheme is M-of-N threshold when there are N signing entities, and M of them are required to generate a valid signature. For example a Bitcoin 2-3 address has a threshold of 2 out of 3 signers. The address requires at least 2 signatures to authorize a spend payment.

Design
======

DarkWallet follows a few basic code design principles including that quality does not necessarily increase with functionality. There is a point where less functionality is a preferable option in terms of practicality and usability.

* **Simplicity**. Simplicity is the most important consideration in a design. It is more important for the implementation to be simple than the interface. 
* **Correctness**. The design should be correct in all aspects.
* **Consistency**. The design should strive for consistenty. Consistency can be sacrificed for simplicity in some cases, but it is better to drop those parts of the design that deal with less common circumstances than to introduce either complexity or inconsistency in the implementation.
* **Completeness**. The design must cover as many important situations as is practical. However completeness must be sacrificed whenever implementation simplicity is jeopardized.

Unix and C are examples of this design. Small building blocks that are flexible in how they combine together.

Generally the API focuses on implementation simplicity and only implements the bare neccessary functionality. Keep implementation simple and don't pollute class interfaces.

**Classes do not implement more functionality than is neccessary.**

Anonymity
=========

We define a cryptocurrency scheme which is anonymous to have 2 primary properties:

* There is no link between transactions, with the anonymity set being infinite (the entire chain).
* Amounts being transacted are completely anonymous.

Additionally other metadata such as network traffic should be anonymized through mixnetworks.

Theory
======

The DarkWallet system operates through 4 core concepts: activity, the credential, the attribute and zero-knowledge proofs.

The highest level concept is that of activity. Activity is a process or operation. It could be granting a user access to a certain file, placing a bid order on an exchange or making a post on a forum.

A credential is required for an activity to succeed. The form of the credential is decided by the programmer, who specifies what the activity requires from the credential in order to succeed. For example with accessing a file, an activity could specify the user must be a member of the moderator, administrator or operator roles.

Each credential consists of a fixed number of attributes. Each attribute contains an integer value. These values can be huge since they are bls12-381 scalars. Attributes are by default encrypted and hidden, but they can be selectively revealed with their signature remaining valid.

Instead of revealing attributes publicly everytime we wanted to prove a statement about our credential, we instead provide zero-knowledge proofs. For example when we split a coin, we prove that the value of the coin going in is the same as the value of the coins being produced. Everybody can verify this basic fact without knowledge of the attribute values inside the credential.

