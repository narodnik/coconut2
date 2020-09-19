# DarkWallet

> Your Keys. Your Privacy. Your Sovereignty.

Your main entry point is the file `examples/simple.rs`. Run it and the unit tests with these commands:

```console
$ git clone https://github.com/narodnik/darkwallet
$ cd darkwallet
$ cargo run --example simple
$ cargo test -- --nocapture
```

That is the basic core of the tech.

For the docs, you need sphinx-build (Python documentation generator):

```console
$ cd doc/
$ make html
```

## Network Infra

Run these commands in separate terminals:

```console
$ cargo run --bin adamd
$ cargo run --bin titand
$ cargo run --example client
```

This network stuff was never completed. But the serialization of types is done. This part might need to be redone.

Also take a look at:

```console
$ cargo build --example df
$ ./examples/anontx.sh
```

Requires some minor fixes to get working again.

# Roadmap

1. Finalize API changes
2. Serialization and network services
3. Product

# TODO

1. ~~`Proof::derive()` should be expired. Collect responses from witnesses. Use them to reinitialize `Proof` during proving stage.~~
1. ~~Split up `schema/asset.rs`~~
1. ~~Attributes as their own class with an index value~~
1. Make sure indexes passed to Coconut attributes are sane, otherwise fail. Shouldn't be asserts esp in server code.
1. Serializable types
1. ~~Tutorial documentation~~
1. Add smaller unit tests for `schema/` objects
1. API documentation
1. Daemonize processes, design protocol
1. Fix all the warnings
1. General code cleanup
1. Profile code sections

# Misc

Uses the [pairing library](https://electriccoin.co/blog/pairing-cryptography-in-rust/) written by ZCash project. Originally `pairing` library, now renamed to `bls12_381`.

