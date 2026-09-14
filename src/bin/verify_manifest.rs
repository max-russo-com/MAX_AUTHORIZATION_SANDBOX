use max_authorization_challenge::verify_maxsig_manifest;
use std::{fs, process};

fn deny(reason: &str) -> ! {
    eprintln!("DENY: {reason}");
    process::exit(1);
}

fn main() {
    let manifest = fs::read("manifest.json")
        .unwrap_or_else(|_| deny("manifest unavailable"));

    let maxsig = fs::read("manifest.challenge.maxsig")
        .unwrap_or_else(|_| deny("MAXSIG unavailable"));

    let trusted_public_key = fs::read("trusted_admin_public.key")
        .unwrap_or_else(|_| deny("trusted admin public key unavailable"));

    verify_maxsig_manifest(
        &manifest,
        &maxsig,
        &trusted_public_key,
    )
    .unwrap_or_else(|reason| deny(reason));

    println!("MAXSIG_OK");
    println!("MANIFEST_HASH_OK");
    println!("SIGNED_PAYLOAD_OK");
    println!("TRUSTED_ADMIN_SIGNATURE_OK");
}
