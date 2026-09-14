# MAX Authorization Sandbox

A local, reproducible sandbox for testing a signed authorization model.

The goal is simple: determine whether a deterministic implementation correctly enforces a human-signed authorization policy and refuses actions that are not explicitly authorized.

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

## Relationship to MAX

This repository is a small, isolated implementation of the authorization model explored in the broader MAX project.

It is intended to make the core trust-chain concept easy to inspect, reproduce, challenge, and audit independently.

It does not establish the security of MAX App, MAX IoT, or any other system. Those systems require their own review, validation, adversarial testing, and independent audit.

## Security scope

This repository is a local research artifact. It does not authorize testing against external services, third-party systems, or production systems.

See `SECURITY.md` for scope and reporting guidance.

## Limitations

A demonstrated authorization failure would apply to this implementation and its tested trust assumptions.

An unsuccessful test does not prove the absolute security of MAX, MAX IoT, SPHINCS+, post-quantum signatures, or authorization systems in general. It means only that no authorization failure was demonstrated within the tested scope and conditions.

## License

This repository is released under the MIT License. See `LICENSE`.
