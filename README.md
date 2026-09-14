# MAX Authorization Sandbox

Repository locale e riproducibile derivata dalla MAX Authorization Challenge 2026.

Questa versione conserva la baseline tecnica originale e la rende disponibile come laboratorio locale indipendente da CTFd e da servizi remoti.

## Contenuto

La repository include il codice Rust, gli artefatti firmati della baseline, la chiave pubblica amministrativa dedicata, la configurazione Docker e i test automatici.

## Principio

La macchina applica una politica firmata e consente soltanto le azioni esplicitamente previste dal manifest valido. Tutto ciò che non è autorizzato deve essere negato.

## Esecuzione

La sandbox è progettata per essere eseguita esclusivamente su sistemi controllati dall'utente, tramite Rust o Docker.

Alcuni nomi interni mantengono il termine `challenge` perché fanno parte della baseline originale e degli artefatti distribuiti.

## Risultati

I risultati ottenuti riguardano soltanto questa implementazione e le condizioni in cui viene eseguita. Un esito negativo non costituisce una prova assoluta di sicurezza di MAX, SPHINCS+ o di altri sistemi.
