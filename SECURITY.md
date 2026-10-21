# Security policy

## Data handling
Migration packages may contain highly sensitive customer files. Store them only on approved encrypted media or storage, restrict access, and securely dispose of temporary packages according to Pixel IT policy.

## Credential policy
This application must not extract Windows password hashes, Windows Credential Manager secrets, browser passwords, cookies, or authentication tokens. Use vendor-supported export/import, account sync, certificate export with explicit authorisation, and reauthentication checklists instead.

## Reporting
Logs and reports must not contain file contents, passwords, encryption keys, tokens, or other secrets. Use job IDs and relative paths where possible.

## Release status
This repository is a prototype until threat modelling, dependency review, automated tests, Windows integration tests, recovery testing, and code-signing/release controls are complete. Never rely on this tool as the only backup.
