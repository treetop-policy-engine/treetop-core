# Generated authorization boundary tests

`tests/authorization_properties.rs` uses Proptest to explore combinations of
Unicode identities, quoting, namespaces, wire data, forged label attributes,
ordered label dependencies, and policy-store rules. Each property runs 256
generated cases by default, shrinking failures to a smaller reproducer.
The generated policy checks compare both engines against an independent rule
model, including group membership, conditions, exceptions, permit/forbid
precedence, returned policy IDs, and engine versions.

Run the suite with either feature configuration:

```bash
cargo test --locked --test authorization_properties
cargo test --locked --all-features --test authorization_properties
```

Increase coverage or replay a particular random run:

```bash
PROPTEST_CASES=2048 PROPTEST_RNG_SEED=12345 \
  cargo test --locked --test authorization_properties
```

Failures persist seeds in
`tests/authorization_properties.proptest-regressions`. Commit new failure seeds
with the fix and add a focused semantic regression when a failure reveals an
authorization bug. Never delete a seed to make the suite pass. Preserve the
reported minimized input when changing a strategy makes an old seed generate a
different case. See Proptest's
[failure persistence documentation](https://proptest-rs.github.io/proptest/proptest/failure-persistence.html).

Proptest is a development-only dependency with its `std` feature enabled.
Shrinking and failure persistence justify this dependency; subprocess/fork and
timeout features are disabled. It does not affect production dependencies or
the evaluation path. CI runs the properties with both default and all features.
