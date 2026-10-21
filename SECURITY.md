# Security policy

## Data handling
Migration packages may contain highly sensitive customer files. Store them only on approved encrypted media or storage, restrict access, and securely dispose of temporary packages according to Pixel IT policy.

## Package protection

Packages use a passphrase-derived key to wrap a random data key and AES-GCM authenticated encryption for the manifest and file chunks. Use a unique, high-entropy passphrase and transfer it through a separate approved channel. Do not store the passphrase beside the package. The alpha package format is not digitally signed: encryption and integrity checks do not prove who created the package or which source computer it came from. The chunked package format is not compatible with earlier alpha packages; recreate older packages using the current build.

## Credential policy
This application must not extract Windows password hashes, Windows Credential Manager secrets, browser passwords, cookies, or authentication tokens. Use vendor-supported export/import, account sync, certificate export with explicit authorisation, and reauthentication checklists instead.

## Reporting
Logs and reports must not contain file contents, passwords, encryption keys, tokens, or other secrets. Use job IDs and relative paths where possible.

## Release status
This repository is a prototype until threat modelling, dependency review, automated tests, Windows integration tests, recovery testing, and code-signing/release controls are complete. Never rely on this tool as the only backup.
