# MAX Authorization Challenge — Threat Model v0.1

## Purpose

This document defines what the MAX Authorization Challenge is intended to test.

This is an authorized defensive security sandbox owned by the project author.

It is deliberately isolated from production MAX systems, real credentials, real user data, and third-party infrastructure.

## Security property under test

The sandbox should execute only actions explicitly authorized by a valid human-signed manifest.

The initial active manifest authorizes:

- STATUS
- PING

It does NOT authorize:

- READ_SECRET

The primary security goal is therefore:

READ_SECRET must remain unavailable unless it is explicitly authorized by a valid manifest signed by the trusted administrative key.

## Attacker knowledge

A participant may know:

- the public source code of the sandbox;
- the manifest format;
- the active manifest;
- the SPHINCS+ signature;
- the trusted administrative public key;
- the API format;
- the documented authorization logic;
- the challenge rules.

Security MUST NOT depend on hiding these elements.

## Attacker capabilities in scope

Within the dedicated local challenge sandbox, a participant may:

- send valid and invalid commands;
- modify request fields;
- submit malformed requests;
- submit modified manifests;
- submit manifests signed with unauthorized keys;
- replay previously observed requests or manifests;
- test unusual encodings and boundary cases;
- send concurrent requests;
- create custom clients;
- use automated scripts;
- use fuzzing;
- use AI systems, autonomous AI Agents, multi-agent systems, or other automated analysis tools.

All of the activities above are authorized only against the participant's own local challenge sandbox.

The remote verifier is not an authorized environment for exploration, fuzzing, replay testing, concurrency testing, scanning, brute force, autonomous probing, or automated attack activity.

The remote verifier may be used only manually and only for requests reasonably necessary to confirm a specific technique that has already been developed and validated locally.

## Security failures in scope

Examples of failures that may count as a successful bypass include:

- READ_SECRET is executed even though it is not authorized;
- a modified manifest is accepted without a valid trusted signature;
- a manifest signed by an unauthorized key is accepted;
- an invalid manifest or invalid persistent policy state is accepted;
- replay causes an unauthorized state change;
- a rollback or same-sequence policy conflict allows unauthorized execution;
- parsing inconsistencies bypass authorization;
- an alternate execution path bypasses the authorization check;
- a race condition exposes the secret.

## Out of scope

The following are NOT valid challenge attacks:

- attacks against GitHub infrastructure;
- attacks against Hugging Face infrastructure;
- account takeover;
- credential theft;
- phishing or social engineering;
- theft of the project author's private keys;
- theft of MAX recovery phrases;
- attacks against production MAX systems;
- attacks against third-party systems;
- physical attacks;
- denial-of-service attacks;
- attempts to cause infrastructure damage;
- malware deployment;
- exploitation outside the dedicated sandbox.

## Trust assumptions

The initial version assumes:

1. the configured administrative public key is correct;
2. the administrative private key remains secret;
3. the cryptographic library performs SPHINCS+ verification as specified;
4. the deployment platform correctly protects configured environment secrets;
5. the operating system and hosting platform are not themselves compromised.

These assumptions may be reduced in later versions.

## Default deny

Any action not explicitly listed in allowed_actions MUST be denied.

Any error, ambiguity, invalid state, or failed verification MUST result in denial.

## Success condition

A participant wins the challenge only if they obtain the exact challenge secret while READ_SECRET is not authorized by the active valid manifest.

Crashes, error messages, denial-of-service, or unrelated bugs do not by themselves constitute success.

## Interpretation

A successful bypass demonstrates a failure in this implementation or one of its trust assumptions.

It does NOT automatically demonstrate a failure of SPHINCS+, MAX App, MAX IoT, or the wider MAX ecosystem.

Failure to obtain the secret does NOT prove absolute security.

It means only that no successful bypass was demonstrated within the tested scope and conditions.
