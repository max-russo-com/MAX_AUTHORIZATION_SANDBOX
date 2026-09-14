# MAX Authorization Challenge

## The Challenge

Can you make a machine execute an action that its valid human-signed authorization policy does not allow?

MAX Authorization Challenge is an isolated security sandbox designed to test that question.

The sandbox supports exactly three actions:

- `STATUS`
- `PING`
- `READ_SECRET`

The active signed manifest authorizes:

- `STATUS`
- `PING`

It does **not** authorize:

- `READ_SECRET`

Your goal is simple:

**Obtain the exact challenge secret while `READ_SECRET` is not authorized by the active valid manifest.**

---

## Security Model

Authorization is deterministic.

The machine does not decide whether an action is allowed based on natural-language instructions, AI judgment, user intent, or persuasion.

An action may execute only when it is explicitly authorized by the active valid manifest.

Anything not explicitly authorized must be denied.

The active authorization chain includes:

1. strict MAXSIG parsing;
2. SHA-256 binding to the exact manifest bytes;
3. canonical `signed_text` validation;
4. SPHINCS+ signature verification;
5. verification against the configured trusted administrative public key;
6. strict manifest validation;
7. persistent policy-sequence and rollback checks;
8. exact action authorization.

Any failed verification, malformed state, ambiguity, unknown action, rollback, or authorization failure must fail closed.

---

## Active Manifest

The challenge starts with this policy:

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
```

`READ_SECRET` is intentionally absent from `allowed_actions`.

The distributed MAXSIG binds byte-for-byte to this manifest through its SHA-256 digest.

Changing or reformatting the manifest changes that digest.

---

## Cryptographic Authorization

The challenge uses:

`SPHINCS+-SHA2-128f-simple`

The trusted administrative public key is intentionally distributed with the challenge.

The corresponding administrative private key is not part of the challenge package and is not available to participants.

The verifier must not automatically trust a public key supplied inside participant-controlled authorization data.

Security is not intended to depend on hiding:

- the source code;
- the manifest;
- the manifest format;
- the signature;
- the trusted public key;
- the verifier;
- the authorization logic.

You are encouraged to inspect all of them.

---

## Local Testing

You may build, modify, instrument, fuzz, and experiment with your local copy of the challenge.

For local Docker testing, provide your own disposable secret, for example:

```bash
export CHALLENGE_SECRET='LOCAL_TEST_SECRET'
docker build -t max-authorization-challenge:local .
docker compose up
```

The local secret is only a test value.

Obtaining a secret that you configured yourself on a machine that you control does **not** constitute solving the hosted challenge.

---

## HTTP Interface

The hosted challenge exposes four HTTP endpoints.

### Status

```text
GET /status
```

Expected authorized response:

```text
SYSTEM_OK
```

### Ping

```text
GET /ping
```

Expected authorized response:

```text
PONG
```

### Read Secret

```text
GET /read-secret
```

With the initial active manifest, `READ_SECRET` is not authorized.

The expected response is denial.

### Verify and Execute Candidate Artifacts

```text
POST /verify-and-execute
```

This endpoint allows you to submit candidate authorization artifacts to the hosted verifier.

The request body must be JSON:

```json
{
  "action": "READ_SECRET",
  "manifest_b64": "...",
  "maxsig_b64": "..."
}
```

The `action` field must be exactly one of:

- `STATUS`
- `PING`
- `READ_SECRET`

`manifest_b64` and `maxsig_b64` contain the exact candidate manifest and MAXSIG bytes encoded with Base64.

The participant controls the requested action, candidate manifest, and candidate MAXSIG.

The participant does **not** control the trusted administrative public key.

The server always verifies candidates using its configured server-side `trusted_admin_public.key`.

For a candidate request to succeed, the server must:

1. accept the request within the published size limit;
2. parse the JSON request;
3. decode the candidate artifacts;
4. verify the MAXSIG and candidate manifest using the trusted administrative public key;
5. apply policy-sequence and rollback rules;
6. confirm that the requested action is authorized by that verified manifest;
7. only then execute the requested action.

Typical denial behavior includes:

- malformed JSON, unknown actions, or invalid Base64 → HTTP `400`;
- invalid MAXSIG, invalid manifest, rollback, conflict, or unauthorized action → HTTP `403`;
- request body larger than 128 KiB → HTTP `413`.

Successful execution of an authorized action returns HTTP `200`.

Submitting a modified manifest with the original MAXSIG is expected to fail because the MAXSIG is bound to the exact manifest bytes.

---

## What You May Test

Within the dedicated local challenge sandbox, you may:

- inspect all distributed source code;
- build modified local versions;
- create custom clients;
- send valid and malformed requests;
- test unusual encodings and boundary cases;
- test parsing behavior;
- analyze the manifest and MAXSIG formats;
- attempt signature or key-confusion attacks;
- investigate authorization logic;
- investigate policy-state and rollback behavior;
- replay requests;
- test alternate execution paths;
- test concurrency;
- use scripts, fuzzers, AI systems, autonomous AI Agents, multi-agent systems, or other automated analysis tools.

All of the activities above are authorized only against the participant’s own local challenge sandbox.

The remote verifier is not an authorized environment for exploration, fuzzing, replay testing, concurrency testing, scanning, brute force, autonomous probing, or automated attack activity.

The remote verifier may be used only manually and only for requests reasonably necessary to confirm a specific technique that has already been developed and validated locally.

A vulnerability counts only if it can be demonstrated against the dedicated hosted challenge in accordance with the published Rules and authorization scope.

---

## What Is Out of Scope

The following do not constitute valid challenge attacks:

- attacks against CTFd or the hosting provider;
- attacks against GitHub or other external services;
- host or Docker-daemon compromise;
- control-plane or orchestration compromise;
- direct reading of deployment environment variables;
- direct access to the server filesystem or challenge state volume;
- theft of administrative private keys;
- account takeover;
- credential theft;
- phishing or social engineering;
- malware deployment;
- denial-of-service attacks;
- attacks against production MAX systems;
- attacks against third-party systems;
- physical attacks;
- infrastructure damage.

Do not target anything except the dedicated challenge sandbox.

---

## Success Condition

The challenge is solved only if you obtain the **exact secret from the hosted challenge instance while `READ_SECRET` is not authorized by the active valid manifest**.

Examples of things that do not by themselves count as a solution:

- crashing the service;
- causing a denial of service;
- receiving an interesting error message;
- modifying your own local copy;
- replacing the trusted key in your own environment;
- changing your own manifest;
- reading a secret that you configured locally;
- compromising infrastructure outside the sandbox.

If you believe you have found a valid bypass, it must be reproducible within the defined challenge scope.

---

## Trust Assumptions

The challenge assumes that:

1. the configured trusted administrative public key is correct;
2. the corresponding administrative private key remains secret;
3. the SPHINCS+ implementation performs verification as specified;
4. the hosting platform correctly protects deployment secrets;
5. the operating system, container runtime, and hosting control plane are not already compromised.

The challenge tests authorization enforcement within those assumptions.

---

## Interpretation of Results

A successful bypass demonstrates a failure in this implementation or in one of the assumptions explicitly included in the challenge.

It does **not** automatically demonstrate that:

- the underlying authorization model is universally insecure;
- SPHINCS+ is broken;
- human-signed authorization cannot work;
- AI systems can generally bypass human authority;
- other systems built around similar principles are insecure.

Likewise, failure to obtain the secret does not prove absolute security.

It means only that:

**No bypass was demonstrated within the tested scope and conditions.**

---

## Why This Challenge Exists

This challenge did not start as an isolated CTF exercise.

It comes from an existing authorization architecture built around a simple principle: a machine should perform only the actions explicitly permitted by a manifest signed by a human authority.

The identity of the requester does not expand that authority. Whether a request comes from a person, software, an AI agent, or another machine, the machine should remain constrained by the permissions contained in the signed manifest.

This challenge isolates that principle and exposes it to adversarial testing.

The question is deliberately simple:

**Can you make the machine do something the human-signed manifest does not authorize?**

The wider project includes working software and IoT components built around this model. The challenge itself remains strictly separated from those systems and uses dedicated test infrastructure, identities, keys, and secrets.

MAX stands for **Mathematical Authorization eXchange**.

Further background and project information are available on the official project website.

---

## Responsible Testing

This is an intentionally vulnerable-or-not-yet-proven-vulnerable sandbox created for authorized adversarial testing.

Stay within scope.

Find the authorization failure.

If there is one.
