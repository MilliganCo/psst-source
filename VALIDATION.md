# Source snapshot verification — 2026-10-29

## Passed on Windows in this isolated copy

- `cargo check --locked --offline -p pwd-core -p pwd-server`.
- `cargo test --locked --offline -p pwd-core --lib`: **50 passed**.
- New TLS file-lifecycle tests: **6 passed**, using opaque synthetic bytes in temporary directories.
- Frontend locked dependency installation with package scripts disabled; Svelte check **0 errors/0 warnings**.
- Frontend unit suite: **24 passed in 5 files**; Vite production build passed.
- `cargo check --locked --offline -p pwd-app` after frontend build: passed.

The first offline npm attempt lacked a cached package; locked dependencies were then fetched into
this copy with `--ignore-scripts`. No CLI/model/server/app/installer/update/HIBP request was run.

## TLS source changes

New identity files use exclusive creation. The private key is written first and DER marker last;
partial, nonregular, orphaned or corrupt identity state fails closed instead of silently rotating
or overwriting it. New Unix keys request 0600 before their first write. This is a file-lifecycle
improvement, not a new crypto protocol or a migration of any installed identity.

NOT RUN — two Unix-only permission tests (the existing Ubuntu WSL startup timed out), live TLS
handshake, Windows ACL validation, real account/vault/device synchronization, GUI, installers and
binary-source reproduction. Existing filesystem permissions are not repaired or attested.

## Publication scope

Old Git history, seven opaque release bundles, real profiles/config/keys/databases and the legacy
encrypted-vault fixture are omitted. Its coupled fixture tests are omitted while production
legacy-import implementation remains. The only .exe is the pinned 23-byte ASCII updater dummy.
Asset attribution and seven exact license texts are retained under licenses/ and THIRD_PARTY_NOTICES.txt.
Public source visibility and these tests do not constitute independent cryptographic assurance.
