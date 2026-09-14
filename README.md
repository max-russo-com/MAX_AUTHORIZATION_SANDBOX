# MAX Authorization Sandbox

A local, reproducible authorization sandbox derived from the 2026 MAX Authorization Challenge.

This repository preserves the original technical baseline and makes it available as a self-contained local laboratory. It has no dependency on CTFd, Render, a hosted verifier, or any production MAX infrastructure.

## Purpose

The sandbox evaluates whether a deterministic implementation correctly enforces a human-signed authorization policy.

A valid signed manifest defines the actions that are allowed. Anything not explicitly authorized must be denied.

The baseline exposes three actions:

- `STATUS`
- `PING`
- `READ_SECRET`

The distributed valid manifest authorizes `STATUS` and `PING`, but not `READ_SECRET`.

## Evaluation criterion

The local secret is intentionally not valuable and may be chosen by the person running the sandbox. Knowing the secret value is therefore not the objective.

The meaningful security property is whether the official unmodified baseline can be made to execute `READ_SECRET` while the active valid manifest still does not authorize that action.

Researchers may modify separate copies for analysis, debugging, instrumentation, testing, or experimentation. Any claimed result should ultimately be reproducible against the official baseline without modifying or removing the authorization enforcement being evaluated.

## Contents

The repository includes the Rust authorization implementation, the signed baseline manifest, the dedicated trusted administrative public key, SPHINCS+ / MAXSIG verification logic, persistent policy-state and rollback protection, Docker packaging, and automated tests.

No production MAX private keys, production credentials, production data, or third-party infrastructure are included.

## Running locally

The sandbox is intended to run only on systems controlled by the user.

With Rust installed:

```bash
cargo test --locked
cargo run -- status
cargo run -- ping
cargo run -- read-secret
```

The baseline should allow `status` and `ping` and deny `read-secret`.

To provide a local test secret:

```bash
export CHALLENGE_SECRET='LOCAL_TEST_SECRET'
```

The historical environment-variable and binary names retain the word `challenge` because they are part of the preserved baseline.

With Docker:

```bash
docker build -t max-authorization-sandbox:local .
CHALLENGE_SECRET='LOCAL_TEST_SECRET' docker compose up
```

The Docker Compose configuration publishes the service only on the local loopback interface (`127.0.0.1`). No hosted verifier or remote service is required.

## Security scope

This repository is a local research artifact. It does not authorize testing against external services, third-party systems, hosted infrastructure, or production MAX systems.

See `SECURITY.md` for scope and reporting guidance.

## Limitations

A demonstrated authorization failure would apply to this implementation and its tested trust assumptions.

An unsuccessful test does not prove the absolute security of MAX, MAX IoT, SPHINCS+, post-quantum signatures, or authorization systems in general. It means only that no authorization failure was demonstrated within the tested scope and conditions.

## License

This repository is released under the MIT License. See `LICENSE`.
