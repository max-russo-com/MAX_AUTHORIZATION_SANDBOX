# MAX Authorization Sandbox

A local, reproducible sandbox for testing a signed authorization model.

The goal is simple: determine whether a deterministic implementation correctly enforces a human-signed authorization policy and refuses actions that are not explicitly authorized.

Project page: https://www.max-russo.com/authorization-sandbox.php

## Purpose

A valid signed manifest defines the actions that are allowed. Anything not explicitly authorized must be denied.

The reference baseline exposes three actions:

- `STATUS`
- `PING`
- `READ_SECRET`

The distributed valid manifest authorizes `STATUS` and `PING`, but not `READ_SECRET`.

## Evaluation criterion

The local secret is intentionally not valuable and may be chosen by the person running the sandbox. Knowing its value is not the objective.

The relevant property is whether the official baseline can be made to execute `READ_SECRET` while the active valid manifest still does not authorize that action.

Researchers may modify separate copies for analysis, debugging, instrumentation, testing, fuzzing, or experimentation. Any claimed authorization bypass should ultimately be reproducible against the official baseline without modifying or removing the authorization enforcement being evaluated.

## Trust model

The baseline uses a signed manifest, one trusted administrative public key, signature verification, explicit allowed actions, persistent policy state, rollback protection, and default-deny behavior.

The repository includes the Rust implementation, signed baseline artifacts, the trusted administrative public key, SPHINCS+ / MAXSIG verification logic, Docker packaging, and automated tests.

No production private keys, production credentials, production data, or third-party infrastructure are included.

## Local execution

The sandbox is designed to run on systems controlled by the user.

The Rust implementation can be built and tested locally with Cargo. Docker packaging is also included.

The default Docker Compose configuration publishes no host port, so the container is not exposed as a network service by default.

No remote service is required for the evaluation.

## Quick start

Clone the repository and enter the project directory:

```bash
git clone https://github.com/max-russo-com/MAX_AUTHORIZATION_SANDBOX.git
cd MAX_AUTHORIZATION_SANDBOX
```

Run the baseline tests:

```bash
cargo test --locked
```

Verify the distributed signed manifest:

```bash
cargo run --locked --quiet --bin verify_manifest
```

Check the two authorized actions:

```bash
cargo run --locked --quiet --bin max_authorization_challenge -- status
cargo run --locked --quiet --bin max_authorization_challenge -- ping
```

The expected outputs are `SYSTEM_OK` and `PONG`.

Now set a local test secret and request the unauthorized action:

```bash
CHALLENGE_SECRET=LOCAL_TEST_SECRET cargo run --locked --quiet --bin max_authorization_challenge -- read-secret
```

The baseline should return `DENY` and must not reveal `LOCAL_TEST_SECRET`.

The research objective is to make the official baseline execute `READ_SECRET` while the active valid manifest still does not authorize it, without modifying or removing the authorization enforcement being evaluated.

## Relationship to MAX

This repository isolates and makes testable one authorization principle explored in the broader MAX project: a machine should execute only actions explicitly authorized by a valid policy signed by a trusted administrator.

The sandbox is not a complete representation, replica, or security model of MAX App or MAX IoT. Those systems are broader and require their own review, validation, adversarial testing, and independent audit.

The purpose of this repository is to make this specific authorization and trust-chain principle easy to inspect, reproduce, challenge, and audit independently.

For broader project context, see https://www.max-russo.com/.

## Security scope

This repository is a local research artifact. It does not authorize testing against external services, third-party systems, or production systems.

Reproducible bypasses, technical findings, and related analysis may be reported publicly through this repository's GitHub Issues. See `SECURITY.md` for scope and reporting guidance.

## Limitations

A demonstrated authorization failure would apply to this implementation and its tested trust assumptions.

An unsuccessful test does not prove the absolute security of MAX, MAX IoT, SPHINCS+, post-quantum signatures, or authorization systems in general. It means only that no authorization failure was demonstrated within the tested scope and conditions.

## License

This repository is released under the MIT License. See `LICENSE`.
