# MAX Authorization Challenge

## What this project is

MAX Authorization Challenge is an authorized defensive security sandbox owned by the project author.

It is designed specifically to test one narrow question:

Can a machine be made to execute an action that is not authorized by a valid human-signed policy?

The sandbox does not contain third-party systems, real credentials, production data, or production infrastructure.

## Initial challenge

The sandbox supports three actions:

- STATUS
- PING
- READ_SECRET

The active authorization manifest initially allows:

- STATUS
- PING

It does not allow:

- READ_SECRET

The challenge goal is to obtain the protected secret while READ_SECRET is not authorized by the active valid manifest.

## Authorization model

The machine does not decide based on natural-language instructions or AI judgment.

It follows deterministic authorization rules.

A manifest may become active only if it passes all required checks, including signature verification against the configured trusted administrative public key.

For every requested action, the sandbox checks whether that action is explicitly present in the active manifest's allowed_actions list.

Anything not explicitly allowed is denied.

## Cryptographic authorization

The project verifies MAXSIG authorization artifacts using SPHINCS+ signature verification compatible with the dedicated challenge signing identity.

The administrative private key remains outside the sandbox.

The sandbox contains only the dedicated trusted administrative public key used to verify signed authorization manifests.

The challenge does not trust or automatically adopt public keys supplied inside participant-controlled authorization artifacts.

No production MAX private keys, production identities, or production credentials are used.

## Relationship to MAX

This project is an isolated authorization challenge using a dedicated MAX signing identity created specifically for the sandbox.

The challenge remains separated from production MAX systems, identities, databases, credentials, devices, and infrastructure.

The authorization flow under test is:

human authorization

-> signed manifest

-> MAXSIG verification

-> deterministic machine enforcement

The presence of MAXSIG and SPHINCS+ verification in this sandbox does not make the challenge a proof of security for MAX, MAX IoT, MAX App, or SPHINCS+ as a whole.

## Development path

The current development order is:

1. local authorization sandbox;
2. strict manifest parsing;
3. deterministic authorization engine;
4. fail-closed behavior;
5. dedicated MAXSIG verification;
6. persistent rollback and policy-state protection;
7. automated negative and adversarial tests;
8. concurrency protection for persistent policy state;
9. local service interface using the same authorization core;
10. Docker packaging of the same software;
11. private Hosted CTFd deployment;
12. authorized adversarial testing;
13. review of results and possible publication.

The local sandbox remains the reference implementation. Docker and Hosted CTFd are deployment layers around the same authorization engine, not separate challenge implementations.

## Security principle

The challenge should remain verifiable even if participants know:

- the source code;
- the manifest format;
- the active manifest;
- the signature;
- the administrative public key;
- the authorization logic.

Security must not depend on obscurity.

## Important limitation

A successful attack demonstrates a failure in this implementation or one of its trust assumptions.

An unsuccessful attack does not prove that MAX, MAX IoT, SPHINCS+, or AI authorization systems are absolutely secure.

It means only that no bypass was demonstrated within the defined scope and tested conditions.

## Authorized testing only

All adversarial testing must target only the dedicated challenge sandbox.

Attacks against third-party systems, hosting providers, production infrastructure, credentials, users, or unrelated services are outside the scope of this project.
