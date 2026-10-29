# Psst / Passwords — source snapshot

Rust password-vault core, a Tauri/Svelte desktop interface, and a self-hosted synchronization server. This snapshot is based on source commit d9d186924bbfccc9256ad535ad1ef4b2727497dd.

The publication contains source, build manifests, application icons, licensed generator/chat resources and synthetic tests. It contains no release archives, Git history, runtime vaults/databases, TLS private keys, server configuration, real accounts or service installation scripts.

## Review boundary

Source inspection traced the account, KDF, authenticated-encryption, login/session, TLS-pinning and updater boundaries. Demonstration passwords occur in temporary tests and the DEV-only browser preview; they are not installed production accounts. This is not an independent cryptographic assurance or a reproducible-binary certification.

The core uses Argon2id/HKDF and XChaCha20-Poly1305; sharing uses public-key key envelopes. Correct composition, recovery, multi-device behavior and every runtime edge require their own validation. Publishing source does not certify an already installed copy or its filesystem permissions.

## Neutral build/check setup

Use a separate checkout and the lockfiles. With dependencies already cached, the following commands perform finite offline checks:

```powershell
cargo check --locked --offline -p pwd-core -p pwd-server
cargo test --locked --offline -p pwd-core --lib
npm --prefix app ci --ignore-scripts --offline
npm --prefix app run check
npm --prefix app test
npm --prefix app run build
```

Missing cached dependencies should be reported; these commands do not silently fetch them. Rust desktop compilation additionally needs the operating system's Tauri build prerequisites. No application/server launch, account registration, HIBP query, updater download, release packaging or signing is needed for these checks.

For any future manual desktop preview, first set PWD_DATA_DIR to a fresh private test directory. The normal application identifier can otherwise select the installed application's profile. Use new synthetic data and leave the server disconnected during local UI work. The original E2E launch scripts and service installers are outside this source-only snapshot.

The legacy encrypted-vault fixture and its dependent fixture tests are omitted. Import support remains source, while that historical fixture is not redistributed. Signed-update tests retain a 23-byte ASCII dummy named .exe plus public verification material; that file is not an executable installer or a release artifact.

## Deployment and trust notes

The source snapshot hardens new TLS identity creation: exclusive files, no silent replacement of existing/partial identities, and an owner-only Unix key mode before writing. Six portable file-lifecycle tests pass on Windows. Unix mode tests were not executed; Windows ACLs and permissions of existing deployments remain separate checks. Use a private directory (0700 on Linux or an appropriate owner-only Windows ACL). This snapshot does not change installed profiles or server identities.

The updater's embedded verification key is public provenance material, not a signing secret. A maintained fork needs its own trust/release policy; no private signing key is supplied or generated here. Historical installation, performance, migration and automatic-update claims are not verified by this source-only packaging review.

## Attribution

See THIRD_PARTY_NOTICES.txt and licenses/. The EFF wordlist is stored without its dice-code column. The chat font is an 80-glyph WOFF subset of Symbols Nerd Font Mono 3.5.1 with the relevant component notices. Overall project-license selection remains with the owner; these asset licenses do not relabel the entire application's source.


Actual publication-copy checks: [VALIDATION.md](VALIDATION.md). This is a source preview; no binary release or installed-version security attestation is supplied.
