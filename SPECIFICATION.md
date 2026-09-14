# MAX Authorization Challenge — Specification v0.1

## Scope

This project is an authorized defensive security sandbox owned by the project author.

It is designed specifically for security testing and contains no third-party systems, credentials, production data, or production infrastructure.

The goal is to verify whether a machine correctly enforces a human-signed authorization policy and rejects unauthorized actions.

## Actions

The sandbox supports exactly three actions:

- STATUS
- PING
- READ_SECRET

Expected behavior:

- STATUS -> returns SYSTEM_OK
- PING -> returns PONG
- READ_SECRET -> returns the challenge secret only if explicitly authorized

## Default deny

Any action that is not explicitly present in the active manifest's allowed_actions list MUST be denied.

## Manifest

The active manifest contains:

- schema
- challenge_id
- version
- policy_sequence
- allowed_actions
- nonce

The current V1 manifest is:

```json
{
  "schema": "max-authorization-challenge/v1",
  "challenge_id": "MAX-AUTHORIZATION-CHALLENGE-001",
  "version": 1,
  "policy_sequence": 1,
  "allowed_actions": [
    "STATUS",
    "PING"
  ],
  "nonce": "MAC-V1-NONCE-001"
}

READ_SECRET is intentionally absent from allowed_actions.

The manifest is bound byte-for-byte to its MAXSIG through its SHA-256 digest. Reformatting or modifying the manifest changes the digest and invalidates the signed authorization artifact.

Administrative trust

The sandbox trusts exactly one dedicated administrative public key.

A manifest may become active only if:

the MAXSIG structure is valid;
the manifest SHA-256 matches the hash declared by MAXSIG;
signed_text exactly matches the expected manifest hash binding;
the administrator signature verifies against the configured trusted public key;
the recovered signed payload is valid and binds the same signed_text;
the manifest structure and values are valid;
policy sequence and persistent state checks succeed.

The challenge must not trust or automatically adopt a public key supplied inside participant-controlled MAXSIG data.

If any verification step fails, the manifest MUST be rejected.

Command authorization

For every requested action:

a valid signed manifest must exist;
policy state checks must succeed;
the requested action must appear exactly in allowed_actions.

Otherwise the result MUST be DENY.

Unknown actions, malformed manifests, signature failures, rollback attempts, conflicting policy state, or invalid persistent state must fail closed.

## Secret

The challenge secret MUST NOT be stored in source code or committed to Git.

It will be provided to the sandbox through a local environment variable during development and through an isolated secret mechanism during deployment.

## Challenge success condition

The challenge is considered broken if a participant obtains the exact challenge secret while READ_SECRET is not authorized by the active manifest.

## Fail closed

Any parsing error, signature error, invalid manifest state, missing authorization data, or unexpected internal state MUST result in denial.

## Initial development constraints

The first implementation is local only.

Do not connect this version to:

- production MAX systems;
- production MAX identities;
- production private keys;
- production databases;
- real IoT devices;
- third-party systems.

A dedicated test identity and dedicated test cryptographic material will be used.

## Interpretation of results

Failure to obtain the secret does NOT prove that MAX, MAX IoT, SPHINCS+, or this sandbox is absolutely secure.

It means only that no successful bypass was demonstrated within the tested implementation, threat model, and conditions.
