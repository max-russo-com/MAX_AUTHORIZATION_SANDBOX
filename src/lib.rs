use base64::{engine::general_purpose::STANDARD, Engine as _};
use pqcrypto_sphincsplus::sphincssha2128fsimple as spx;
use pqcrypto_traits::sign::{PublicKey as _, SignedMessage as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const EXPECTED_SCHEMA: &str = "max-authorization-challenge/v1";
pub const EXPECTED_CHALLENGE_ID: &str = "MAX-AUTHORIZATION-CHALLENGE-001";
pub const EXPECTED_VERSION: u32 = 1;

// Algoritmo MAXSIG atteso dalla challenge.
pub const EXPECTED_MAXSIG_ALG_LABEL: &str = "SPHINCS+-SHA2-128f-simple";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub challenge_id: String,
    pub version: u32,
    pub policy_sequence: u64,
    pub allowed_actions: Vec<String>,
    pub nonce: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Status,
    Ping,
    ReadSecret,
}

impl Action {
    pub fn as_manifest_name(self) -> &'static str {
        match self {
            Action::Status => "STATUS",
            Action::Ping => "PING",
            Action::ReadSecret => "READ_SECRET",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaxSigFile {
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaxSig {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    alg: String,
    file: MaxSigFile,
    signed_text: String,
    signature_b64: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPayload {
    mods: Vec<u64>,
    modsig: String,
    msg: String,
    nonce: String,
    primes: Vec<String>,
    res: Vec<u64>,
    root: String,
}

pub fn validate_manifest(manifest: &Manifest) -> Result<(), &'static str> {
    if manifest.schema != EXPECTED_SCHEMA {
        return Err("unexpected manifest schema");
    }

    if manifest.challenge_id != EXPECTED_CHALLENGE_ID {
        return Err("unexpected challenge_id");
    }

    if manifest.version != EXPECTED_VERSION {
        return Err("unsupported manifest version");
    }

    if manifest.policy_sequence == 0 {
        return Err("invalid policy_sequence");
    }

    if manifest.nonce.trim().is_empty() {
        return Err("empty nonce");
    }

    let mut seen = HashSet::new();

    for action in &manifest.allowed_actions {
        match action.as_str() {
            "STATUS" | "PING" | "READ_SECRET" => {}
            _ => return Err("unknown action in allowed_actions"),
        }

        if !seen.insert(action.as_str()) {
            return Err("duplicate action in allowed_actions");
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyState {
    pub highest_sequence: u64,
    pub active_manifest_hash: String,
}

pub fn validate_policy_state(state: &PolicyState) -> Result<(), &'static str> {
    if state.highest_sequence == 0 {
        return Err("invalid policy state sequence");
    }

    if state.active_manifest_hash.len() != 64
        || !state
            .active_manifest_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid policy state hash");
    }

    Ok(())
}


pub enum PolicyStateDecision {
    Initialize,
    KeepCurrent,
    Advance,
}

pub fn check_policy_state(
    current: Option<&PolicyState>,
    manifest_sequence: u64,
    manifest_hash: &str,
) -> Result<PolicyStateDecision, &'static str> {
    if let Some(state) = current {
        validate_policy_state(state)?;
    }

    match current {
        None => Ok(PolicyStateDecision::Initialize),

        Some(state) if manifest_sequence < state.highest_sequence => {
            Err("policy rollback detected")
        }

        Some(state) if manifest_sequence == state.highest_sequence
            && manifest_hash != state.active_manifest_hash =>
        {
            Err("policy sequence conflict")
        }

        Some(state) if manifest_sequence == state.highest_sequence => {
            Ok(PolicyStateDecision::KeepCurrent)
        }

        Some(_) => Ok(PolicyStateDecision::Advance),
    }
}


pub fn is_allowed(manifest: &Manifest, action: Action) -> bool {
    if validate_manifest(manifest).is_err() {
        return false;
    }

    manifest
        .allowed_actions
        .iter()
        .any(|allowed| allowed == action.as_manifest_name())
}

pub fn verify_maxsig_manifest(
    manifest_bytes: &[u8],
    maxsig_bytes: &[u8],
    trusted_public_key_bytes: &[u8],
) -> Result<Manifest, &'static str> {
    let maxsig: MaxSig =
        serde_json::from_slice(maxsig_bytes).map_err(|_| "invalid MAXSIG JSON")?;

    if maxsig.kind != "MAXSIG" {
        return Err("unexpected MAXSIG type");
    }

    if maxsig.version != 1 {
        return Err("unsupported MAXSIG version");
    }

    if maxsig.alg != EXPECTED_MAXSIG_ALG_LABEL {
        return Err("unexpected MAXSIG algorithm label");
    }

    let digest = Sha256::digest(manifest_bytes);
    let manifest_hash: String =
        digest.iter().map(|b| format!("{b:02x}")).collect();

    if maxsig.file.sha256 != manifest_hash {
        return Err("manifest SHA-256 mismatch");
    }

    let expected_signed_text =
        format!("MAXSIG|v1|sha256={manifest_hash}");

    if maxsig.signed_text != expected_signed_text {
        return Err("signed_text mismatch");
    }

    let signed_message_bytes = STANDARD
        .decode(&maxsig.signature_b64)
        .map_err(|_| "invalid signature base64")?;

    let signed_message =
        spx::SignedMessage::from_bytes(&signed_message_bytes)
            .map_err(|_| "invalid SPHINCS+ signed message")?;

    let trusted_pk =
        spx::PublicKey::from_bytes(trusted_public_key_bytes)
            .map_err(|_| "invalid trusted admin public key")?;

    let recovered_payload =
        spx::open(&signed_message, &trusted_pk)
            .map_err(|_| "invalid administrator signature")?;

    let payload: SignedPayload =
        serde_json::from_slice(&recovered_payload)
            .map_err(|_| "invalid signed payload JSON")?;

    if payload.msg != maxsig.signed_text {
        return Err("signed payload message mismatch");
    }

    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes)
            .map_err(|_| "invalid manifest JSON")?;

    validate_manifest(&manifest)?;

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn restricted_manifest() -> Manifest {
        Manifest {
            schema: EXPECTED_SCHEMA.to_string(),
            challenge_id: EXPECTED_CHALLENGE_ID.to_string(),
            version: 1,
            policy_sequence: 1,
            allowed_actions: vec![
                "STATUS".to_string(),
                "PING".to_string(),
            ],
            nonce: "MAC-V1-NONCE-001".to_string(),
        }
    }

    #[test]
    fn valid_manifest_is_accepted() {
        assert!(validate_manifest(&restricted_manifest()).is_ok());
    }

    #[test]
    fn manifest_with_unknown_field_is_rejected() {
        let json = br#"{
  "schema": "max-authorization-challenge/v1",
  "challenge_id": "MAX-AUTHORIZATION-CHALLENGE-001",
  "version": 1,
  "policy_sequence": 1,
  "allowed_actions": ["STATUS", "PING"],
  "nonce": "TEST-NONCE",
  "unexpected": true
}"#;

        let parsed = serde_json::from_slice::<Manifest>(json);

        assert!(parsed.is_err());
    }

    #[test]
    fn manifest_with_duplicate_field_is_rejected() {
        let json = br#"{
  "schema": "max-authorization-challenge/v1",
  "challenge_id": "MAX-AUTHORIZATION-CHALLENGE-001",
  "version": 1,
  "policy_sequence": 1,
  "allowed_actions": ["STATUS", "PING"],
  "allowed_actions": ["READ_SECRET"],
  "nonce": "TEST-NONCE"
}"#;

        let parsed = serde_json::from_slice::<Manifest>(json);

        assert!(parsed.is_err());
    }

    #[test]
    fn manifest_with_wrong_json_type_is_rejected() {
        let json = br#"{
  "schema": "max-authorization-challenge/v1",
  "challenge_id": "MAX-AUTHORIZATION-CHALLENGE-001",
  "version": 1,
  "policy_sequence": "1",
  "allowed_actions": ["STATUS", "PING"],
  "nonce": "TEST-NONCE"
}"#;

        let parsed = serde_json::from_slice::<Manifest>(json);

        assert!(parsed.is_err());
    }

    #[test]
    fn manifest_with_missing_field_is_rejected() {
        let json = br#"{
  "schema": "max-authorization-challenge/v1",
  "challenge_id": "MAX-AUTHORIZATION-CHALLENGE-001",
  "version": 1,
  "policy_sequence": 1,
  "allowed_actions": ["STATUS", "PING"]
}"#;

        let parsed = serde_json::from_slice::<Manifest>(json);

        assert!(parsed.is_err());
    }





    #[test]
    fn wrong_schema_is_rejected() {
        let mut manifest = restricted_manifest();
        manifest.schema = "wrong".to_string();

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn wrong_challenge_id_is_rejected() {
        let mut manifest = restricted_manifest();
        manifest.challenge_id = "OTHER-CHALLENGE".to_string();

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn zero_policy_sequence_is_rejected() {
        let mut manifest = restricted_manifest();
        manifest.policy_sequence = 0;

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn empty_nonce_is_rejected() {
        let mut manifest = restricted_manifest();
        manifest.nonce.clear();

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn unknown_action_is_rejected() {
        let mut manifest = restricted_manifest();
        manifest.allowed_actions.push("STATUS_ADMIN".to_string());

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn duplicate_action_is_rejected() {
        let mut manifest = restricted_manifest();
        manifest.allowed_actions.push("STATUS".to_string());

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn status_and_ping_are_allowed() {
        let manifest = restricted_manifest();

        assert!(is_allowed(&manifest, Action::Status));
        assert!(is_allowed(&manifest, Action::Ping));
    }

    #[test]
    fn read_secret_is_denied() {
        let manifest = restricted_manifest();

        assert!(!is_allowed(&manifest, Action::ReadSecret));
    }

    #[test]
    fn policy_state_with_unknown_field_is_rejected() {
        let json = br#"{
  "highest_sequence": 1,
  "active_manifest_hash": "abc123",
  "unexpected": true
}"#;

        let parsed = serde_json::from_slice::<PolicyState>(json);

        assert!(parsed.is_err());
    }


    #[test]
    fn policy_state_with_zero_sequence_is_rejected() {
        let state = PolicyState {
            highest_sequence: 0,
            active_manifest_hash:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
        };

        assert!(validate_policy_state(&state).is_err());
    }

    #[test]
    fn policy_state_with_invalid_hash_is_rejected() {
        let state = PolicyState {
            highest_sequence: 1,
            active_manifest_hash: "abc123".to_string(),
        };

        assert!(validate_policy_state(&state).is_err());
    }


    #[test]
    fn policy_state_roundtrip_is_valid() {
        let state = PolicyState {
            highest_sequence: 7,
            active_manifest_hash: "abc123".to_string(),
        };

        let encoded = serde_json::to_vec(&state)
            .expect("policy state should serialize");

        let decoded: PolicyState =
            serde_json::from_slice(&encoded)
                .expect("policy state should deserialize");

        assert_eq!(decoded, state);
    }


    #[test]
    fn check_policy_state_rejects_invalid_current_state() {
        let state = PolicyState {
            highest_sequence: 0,
            active_manifest_hash:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
        };

        let result = check_policy_state(
            Some(&state),
            1,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );

        assert!(result.is_err());
    }


    #[test]
    fn first_policy_initializes_state() {
        let decision = check_policy_state(
            None,
            1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        assert!(matches!(
            decision,
            Ok(PolicyStateDecision::Initialize)
        ));
    }

    #[test]
    fn same_policy_is_accepted_again() {
        let state = PolicyState {
            highest_sequence: 1,
            active_manifest_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        };

        let decision = check_policy_state(
            Some(&state),
            1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        assert!(matches!(
            decision,
            Ok(PolicyStateDecision::KeepCurrent)
        ));
    }

    #[test]
    fn older_policy_is_rejected() {
        let state = PolicyState {
            highest_sequence: 2,
            active_manifest_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };

        let decision = check_policy_state(
            Some(&state),
            1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        assert!(decision.is_err());
    }

    #[test]
    fn same_sequence_with_different_hash_is_rejected() {
        let state = PolicyState {
            highest_sequence: 1,
            active_manifest_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        };

        let decision = check_policy_state(
            Some(&state),
            1,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );

        assert!(decision.is_err());
    }

    #[test]
    fn newer_policy_advances_state() {
        let state = PolicyState {
            highest_sequence: 1,
            active_manifest_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        };

        let decision = check_policy_state(
            Some(&state),
            2,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );

        assert!(matches!(
            decision,
            Ok(PolicyStateDecision::Advance)
        ));
    }


    #[test]
    fn valid_maxsig_is_accepted() {
        let manifest = br#"{
  "schema": "max-authorization-challenge/v1",
  "challenge_id": "MAX-AUTHORIZATION-CHALLENGE-001",
  "version": 1,
  "policy_sequence": 1,
  "allowed_actions": ["STATUS", "PING"],
  "nonce": "TEST-NONCE"
}"#;

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": [
                "11",
                "13",
                "17",
                "19",
                "23"
            ],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn modified_manifest_is_rejected() {
        let original = b"ORIGINAL";
        let modified = b"MODIFIED";

        let digest = Sha256::digest(original);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": [
                "11",
                "13",
                "17",
                "19",
                "23"
            ],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                modified,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn maxsig_with_unknown_field_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": ["11", "13", "17", "19", "23"],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes()),
            "unexpected": true
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn maxsig_with_embedded_public_key_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": [
                "11",
                "13",
                "17",
                "19",
                "23"
            ],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes()),
            "pk_b64": STANDARD.encode(pk.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn wrong_maxsig_type_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": ["11", "13", "17", "19", "23"],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "NOT-MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn wrong_maxsig_version_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": ["11", "13", "17", "19", "23"],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 2,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn wrong_maxsig_algorithm_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": ["11", "13", "17", "19", "23"],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": "UNSUPPORTED-ALGORITHM",
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn altered_signed_text_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let correct_signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": correct_signed_text,
            "nonce": "test-nonce",
            "primes": ["11", "13", "17", "19", "23"],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();
        let signed = spx::sign(payload.as_bytes(), &sk);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": "MAXSIG|v1|sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "signature_b64": STANDARD.encode(signed.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn invalid_base64_signature_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": "%%%NOT-BASE64%%%"
        })
        .to_string();

        let (pk, _) = spx::keypair();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn corrupted_signature_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": [
                "11",
                "13",
                "17",
                "19",
                "23"
            ],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (pk, sk) = spx::keypair();

        let signed = spx::sign(payload.as_bytes(), &sk);

        let mut signed_bytes = signed.as_bytes().to_vec();

        signed_bytes[0] ^= 0x01;

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(&signed_bytes)
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk.as_bytes()
            )
            .is_err()
        );
    }


    #[test]
    fn wrong_public_key_is_rejected() {
        let manifest = b"TEST";

        let digest = Sha256::digest(manifest);
        let hash: String =
            digest.iter().map(|b| format!("{b:02x}")).collect();

        let signed_text =
            format!("MAXSIG|v1|sha256={hash}");

        let payload = json!({
            "mods": [7, 59, 191, 197],
            "modsig": "test-modsig",
            "msg": signed_text,
            "nonce": "test-nonce",
            "primes": [
                "11",
                "13",
                "17",
                "19",
                "23"
            ],
            "res": [2, 3, 5, 7],
            "root": "test-root"
        })
        .to_string();

        let (_pk1, sk1) = spx::keypair();
        let (pk2, _sk2) = spx::keypair();

        let signed = spx::sign(payload.as_bytes(), &sk1);

        let maxsig = json!({
            "type": "MAXSIG",
            "version": 1,
            "alg": EXPECTED_MAXSIG_ALG_LABEL,
            "file": {
                "sha256": hash
            },
            "signed_text": signed_text,
            "signature_b64": STANDARD.encode(signed.as_bytes())
        })
        .to_string();

        assert!(
            verify_maxsig_manifest(
                manifest,
                maxsig.as_bytes(),
                pk2.as_bytes()
            )
            .is_err()
        );
    }
}
