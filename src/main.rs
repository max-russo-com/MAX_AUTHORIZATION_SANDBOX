use max_authorization_challenge::{
    check_policy_state,
    is_allowed,
    verify_maxsig_manifest,
    Action,
    Manifest,
    PolicyState,
    PolicyStateDecision,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fs2::FileExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{env, fs, process};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tiny_http::{Request, Response, Server};
use std::fs::OpenOptions;
use std::io::{Read, Write};

const STATE_FILE: &str = "state/policy_state.json";
const STATE_LOCK_FILE: &str = "state/policy_state.lock";
const MAX_REQUEST_BODY_BYTES: usize = 128 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyExecuteRequest {
    action: String,
    manifest_b64: String,
    maxsig_b64: String,
}

fn deny(reason: &str) -> ! {
    eprintln!("DENY: {reason}");
    process::exit(1);
}

fn load_policy_state() -> Option<PolicyState> {
    match fs::read(STATE_FILE) {
        Ok(bytes) => {
            let state: PolicyState =
                serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| deny("invalid policy state"));

            Some(state)
        }

        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,

        Err(_) => deny("policy state unavailable"),
    }
}

fn save_policy_state(state: &PolicyState) {
    fs::create_dir_all("state")
        .unwrap_or_else(|_| deny("cannot create state directory"));

    let bytes =
        serde_json::to_vec_pretty(state)
            .unwrap_or_else(|_| deny("cannot serialize policy state"));

    let temp_file = "state/policy_state.json.tmp";

    let mut temp = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(temp_file)
        .unwrap_or_else(|_| deny("cannot open temporary policy state"));

    temp.write_all(&bytes)
        .unwrap_or_else(|_| deny("cannot write policy state"));

    temp.sync_all()
        .unwrap_or_else(|_| deny("cannot sync policy state"));

    fs::rename(temp_file, STATE_FILE)
        .unwrap_or_else(|_| deny("cannot commit policy state"));

    fs::File::open("state")
        .and_then(|directory| directory.sync_all())
        .unwrap_or_else(|_| deny("cannot sync policy state directory"));
}

fn load_verified_manifest() -> (Manifest, String) {
    let manifest_bytes =
        fs::read("manifest.json")
            .unwrap_or_else(|_| deny("manifest unavailable"));

    let maxsig_bytes =
        fs::read("manifest.challenge.maxsig")
            .unwrap_or_else(|_| deny("MAXSIG unavailable"));

    let trusted_public_key =
        fs::read("trusted_admin_public.key")
            .unwrap_or_else(|_| deny("trusted admin public key unavailable"));

    let manifest =
        verify_maxsig_manifest(
            &manifest_bytes,
            &maxsig_bytes,
            &trusted_public_key,
        )
        .unwrap_or_else(|reason| deny(reason));

    let digest = Sha256::digest(&manifest_bytes);
    let manifest_hash: String =
        digest.iter().map(|b| format!("{b:02x}")).collect();

    (manifest, manifest_hash)
}

fn try_enforce_policy_state(
    manifest: &Manifest,
    manifest_hash: &str,
) -> Result<(), &'static str> {
    fs::create_dir_all("state")
        .map_err(|_| "cannot create state directory")?;

    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(STATE_LOCK_FILE)
        .map_err(|_| "cannot open policy state lock")?;

    lock_file
        .lock_exclusive()
        .map_err(|_| "cannot lock policy state")?;

    let current = load_policy_state();

    let decision =
        check_policy_state(
            current.as_ref(),
            manifest.policy_sequence,
            manifest_hash,
        )?;

    match decision {
        PolicyStateDecision::Initialize
        | PolicyStateDecision::Advance => {
            let new_state = PolicyState {
                highest_sequence: manifest.policy_sequence,
                active_manifest_hash: manifest_hash.to_string(),
            };

            save_policy_state(&new_state);
        }

        PolicyStateDecision::KeepCurrent => {}
    }

    fs2::FileExt::unlock(&lock_file)
        .map_err(|_| "cannot unlock policy state")?;

    Ok(())
}

fn enforce_policy_state(manifest: &Manifest, manifest_hash: &str) {
    try_enforce_policy_state(manifest, manifest_hash)
        .unwrap_or_else(|reason| deny(reason));
}

#[derive(Debug, PartialEq, Eq)]
enum CandidateRequestError {
    BadRequest,
    Forbidden(&'static str),
}

fn verify_candidate_request(
    body: &[u8],
    trusted_public_key: &[u8],
) -> Result<(Manifest, Action, String), CandidateRequestError> {
    let submitted: VerifyExecuteRequest =
        serde_json::from_slice(body)
            .map_err(|_| CandidateRequestError::BadRequest)?;

    let action = match submitted.action.as_str() {
        "STATUS" => Action::Status,
        "PING" => Action::Ping,
        "READ_SECRET" => Action::ReadSecret,
        _ => return Err(CandidateRequestError::BadRequest),
    };

    let manifest_bytes = STANDARD
        .decode(&submitted.manifest_b64)
        .map_err(|_| CandidateRequestError::BadRequest)?;

    let maxsig_bytes = STANDARD
        .decode(&submitted.maxsig_b64)
        .map_err(|_| CandidateRequestError::BadRequest)?;

    let manifest = verify_maxsig_manifest(
        &manifest_bytes,
        &maxsig_bytes,
        trusted_public_key,
    )
    .map_err(CandidateRequestError::Forbidden)?;

    let digest = Sha256::digest(&manifest_bytes);

    let manifest_hash: String =
        digest.iter().map(|b| format!("{b:02x}")).collect();

    Ok((manifest, action, manifest_hash))
}

fn handle_verify_execute(
    request: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = Vec::new();

    if request
        .as_reader()
        .take((MAX_REQUEST_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .is_err()
    {
        return Response::from_string("DENY\n")
            .with_status_code(400);
    }

    if body.len() > MAX_REQUEST_BODY_BYTES {
        return Response::from_string("DENY\n")
            .with_status_code(413);
    }

    let trusted_public_key =
        fs::read("trusted_admin_public.key")
            .unwrap_or_else(|_| deny("trusted admin public key unavailable"));

    let (manifest, action, manifest_hash) =
        match verify_candidate_request(&body, &trusted_public_key) {
            Ok(result) => result,

            Err(CandidateRequestError::BadRequest) => {
                return Response::from_string("DENY\n")
                    .with_status_code(400);
            }

            Err(CandidateRequestError::Forbidden(reason)) => {
                eprintln!("DENY candidate verification: {reason}");

                return Response::from_string("DENY\n")
                    .with_status_code(403);
            }
        };

    if let Err(reason) =
        try_enforce_policy_state(&manifest, &manifest_hash)
    {
        eprintln!("DENY candidate policy state: {reason}");

        return Response::from_string("DENY\n")
            .with_status_code(403);
    }

    if !is_allowed(&manifest, action) {
        return Response::from_string("DENY\n")
            .with_status_code(403);
    }

    Response::from_string(format!(
        "{}\n",
        execute(&manifest, action)
    ))
    .with_status_code(200)
}

fn execute(manifest: &Manifest, action: Action) -> String {
    if !is_allowed(manifest, action) {
        return "DENY".to_string();
    }

    match action {
        Action::Status => "SYSTEM_OK".to_string(),

        Action::Ping => "PONG".to_string(),

        Action::ReadSecret => {
            env::var("CHALLENGE_SECRET")
                .unwrap_or_else(|_| {
                    deny("challenge secret unavailable")
                })
        }
    }
}

fn serve() {
    let listen_addr =
        env::var("CHALLENGE_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let server = Server::http(&listen_addr)
        .unwrap_or_else(|_| deny("cannot start HTTP server"));

    println!("LISTENING {listen_addr}");

    let running = Arc::new(AtomicBool::new(true));
    let running_for_handler = Arc::clone(&running);

    ctrlc::set_handler(move || {
        running_for_handler.store(false, Ordering::SeqCst);
    })
    .unwrap_or_else(|_| deny("cannot install signal handler"));

    while running.load(Ordering::SeqCst) {
        let mut request = match server.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(Some(request)) => request,
            Ok(None) => continue,
            Err(_) => deny("HTTP receive failed"),
        };

        let response =
            if request.method() == &tiny_http::Method::Get
                && request.url() == "/status"
            {
                let (manifest, manifest_hash) = load_verified_manifest();
                enforce_policy_state(&manifest, &manifest_hash);

                Response::from_string(format!(
                    "{}\n",
                    execute(&manifest, Action::Status)
                ))
                .with_status_code(200)
            } else if request.method() == &tiny_http::Method::Get
                && request.url() == "/ping"
            {
                let (manifest, manifest_hash) = load_verified_manifest();
                enforce_policy_state(&manifest, &manifest_hash);

                Response::from_string(format!(
                    "{}\n",
                    execute(&manifest, Action::Ping)
                ))
                .with_status_code(200)
            } else if request.method() == &tiny_http::Method::Get
                && request.url() == "/read-secret"
            {
                let (manifest, manifest_hash) = load_verified_manifest();
                enforce_policy_state(&manifest, &manifest_hash);

                if !is_allowed(&manifest, Action::ReadSecret) {
                    Response::from_string("DENY\n")
                        .with_status_code(403)
                } else {
                    Response::from_string(format!(
                        "{}\n",
                        execute(&manifest, Action::ReadSecret)
                    ))
                    .with_status_code(200)
                }
            } else if request.method() == &tiny_http::Method::Post
                && request.url() == "/verify-and-execute"
            {
                handle_verify_execute(&mut request)
            } else {
                Response::from_string("DENY\n")
                    .with_status_code(404)
            };

        let _ = request.respond(response);
    }
}


fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("DENY");
        return;
    }

    if args[1] == "serve" {
        serve();
        return;
    }

    let action = match args[1].as_str() {
        "status" => Action::Status,
        "ping" => Action::Ping,
        "read-secret" => Action::ReadSecret,
        _ => {
            println!("DENY");
            return;
        }
    };

    let (manifest, manifest_hash) = load_verified_manifest();

    enforce_policy_state(&manifest, &manifest_hash);

    println!("{}", execute(&manifest, action));
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_request_body(action: &str) -> Vec<u8> {
        let manifest = fs::read("manifest.json")
            .expect("test manifest should be available");

        let maxsig = fs::read("manifest.challenge.maxsig")
            .expect("test MAXSIG should be available");

        serde_json::to_vec(&json!({
            "action": action,
            "manifest_b64": STANDARD.encode(manifest),
            "maxsig_b64": STANDARD.encode(maxsig),
        }))
        .expect("request JSON should serialize")
    }

    fn trusted_public_key() -> Vec<u8> {
        fs::read("trusted_admin_public.key")
            .expect("trusted public key should be available")
    }

    #[test]
    fn valid_status_candidate_is_accepted() {
        let body = valid_request_body("STATUS");

        let result =
            verify_candidate_request(&body, &trusted_public_key())
                .expect("valid candidate should verify");

        let (manifest, action, manifest_hash) = result;

        assert_eq!(action, Action::Status);
        assert!(is_allowed(&manifest, Action::Status));
        assert_eq!(manifest_hash.len(), 64);
    }

    #[test]
    fn valid_artifacts_do_not_authorize_read_secret() {
        let body = valid_request_body("READ_SECRET");

        let (manifest, action, _) =
            verify_candidate_request(&body, &trusted_public_key())
                .expect("valid candidate should verify");

        assert_eq!(action, Action::ReadSecret);
        assert!(!is_allowed(&manifest, Action::ReadSecret));
    }

    #[test]
    fn invalid_candidate_json_is_rejected() {
        let result =
            verify_candidate_request(
                b"{not-json",
                &trusted_public_key(),
            );

        assert!(matches!(
            result,
            Err(CandidateRequestError::BadRequest)
        ));
    }

    #[test]
    fn unknown_candidate_action_is_rejected() {
        let body = serde_json::to_vec(&json!({
            "action": "DELETE_WORLD",
            "manifest_b64": "",
            "maxsig_b64": "",
        }))
        .expect("request JSON should serialize");

        let result =
            verify_candidate_request(&body, &trusted_public_key());

        assert!(matches!(
            result,
            Err(CandidateRequestError::BadRequest)
        ));
    }

    #[test]
    fn invalid_candidate_base64_is_rejected() {
        let body = serde_json::to_vec(&json!({
            "action": "STATUS",
            "manifest_b64": "%%%INVALID%%%",
            "maxsig_b64": "%%%INVALID%%%",
        }))
        .expect("request JSON should serialize");

        let result =
            verify_candidate_request(&body, &trusted_public_key());

        assert!(matches!(
            result,
            Err(CandidateRequestError::BadRequest)
        ));
    }

    #[test]
    fn tampered_manifest_with_original_maxsig_is_rejected() {
        let manifest_bytes = fs::read("manifest.json")
            .expect("test manifest should be available");

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&manifest_bytes)
                .expect("test manifest should parse");

        manifest["allowed_actions"]
            .as_array_mut()
            .expect("allowed_actions should be an array")
            .push(json!("READ_SECRET"));

        let tampered_manifest =
            serde_json::to_vec(&manifest)
                .expect("tampered manifest should serialize");

        let maxsig = fs::read("manifest.challenge.maxsig")
            .expect("test MAXSIG should be available");

        let body = serde_json::to_vec(&json!({
            "action": "READ_SECRET",
            "manifest_b64": STANDARD.encode(tampered_manifest),
            "maxsig_b64": STANDARD.encode(maxsig),
        }))
        .expect("request JSON should serialize");

        let result =
            verify_candidate_request(&body, &trusted_public_key());

        assert!(matches!(
            result,
            Err(CandidateRequestError::Forbidden(
                "manifest SHA-256 mismatch"
            ))
        ));
    }
}
