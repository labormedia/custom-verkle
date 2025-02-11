# custom-verkle
Custom Verkle tree implementation.

This implementation works as a proof of concept on the Pedersen commitment scheme applied to Verkle-type tries. It uses curve25519_dalek crate for all the cryptographic heavy lifting and rand for the random generator.
Debug run of the main example is full of comments about the dynamic internals.

To run in debug mode:
```bash
cargo run
```

To run in release mode:
```bash
cargo run --release
```

Runing tests:
```bash
cargo test --release
```