# MAX Authorization Challenge — Security Notes v0.1

## Authorized scope

This project is an authorized defensive security sandbox owned by the project author.

It exists only to test whether signed authorization policies are correctly enforced.

No third-party systems, credentials, production data, or production infrastructure are part of the challenge.

## Never use production secrets

Do NOT place any of the following in this repository or sandbox:

- production MAX recovery phrases;
- production MAX private keys;
- production MAX identities;
- production database credentials;
- production API keys;
- production server credentials;
- personal data;
- real user data;
- real challenge secrets reused elsewhere.

## Dedicated challenge identity

The challenge must use dedicated test cryptographic material.

The challenge administrative key must be created specifically for this project and must not be reused by production MAX systems.

## Private key handling

The administrative private key must never be committed to Git.

It must never be uploaded to the public challenge server.

Only the administrative public key may be embedded in or distributed with the sandbox.

## Secret handling

The challenge secret must:

- be generated specifically for the challenge;
- not appear in source code;
- not appear in Git history;
- not appear in test fixtures;
- not appear in logs;
- be loaded through a local environment variable during development;
- later be stored using the deployment platform's secret mechanism.

## Repository hygiene

Before any repository becomes public:

- inspect the full Git history;
- inspect configuration files;
- inspect logs;
- inspect test artifacts;
- inspect CI output;
- inspect environment files;
- verify that no private key or secret has ever been committed.

If sensitive material has entered Git history, do not rely only on deleting the file from the latest commit.

Rotate the affected secret and clean or recreate the repository history before publication.

## Fail closed

Security errors must never result in authorization.

Examples:

- invalid signature -> DENY;
- unknown action -> DENY;
- malformed manifest -> DENY;
- missing manifest -> DENY;
- policy rollback -> DENY;
- same-sequence policy conflict -> DENY;
- parser ambiguity -> DENY;
- unexpected internal error -> DENY.

## Separation from MAX production systems

Initial development must remain isolated from:

- MAX App production identities;
- MAX IoT production devices;
- MAX production databases;
- production signing keys;
- real Raspberry Pi devices;
- third-party systems.

Integration with a dedicated MAX signing identity may happen only after the local sandbox passes its tests and review.

## Adversarial testing

Adversarial testing must target only the dedicated sandbox.

Do not test unrelated infrastructure.

Do not attempt destructive activity, denial of service, credential theft, phishing, malware deployment, or attacks against hosting providers.

## Publication principle

The challenge should expose enough information to allow independent verification of the authorization mechanism.

Security must not depend on hiding:

- the verifier code;
- the manifest format;
- the active manifest;
- the signature;
- the trusted administrative public key;
- the authorization rules.

Security should depend on correct implementation and protection of the administrative private key.

## Claims

Do not claim that this challenge proves:

- MAX is secure;
- MAX IoT is secure;
- SPHINCS+ cannot be broken;
- AI cannot bypass human authority in general.

The challenge tests one specific implementation under one defined threat model.
