# Technician workflow (prototype)

1. Obtain customer authorisation and assign a job reference.
2. Confirm a separate backup exists and the source disk is healthy.
3. Run Capture and select the source profile folder (normally the user's profile directory).
4. Review the file list and deselect unnecessary or cloud-only content as appropriate.
5. Choose a package location with adequate free space and use a unique strong passphrase. Store the passphrase separately from the package.
6. Transfer the package securely to the destination PC.
7. Choose the destination profile folder and run Preview restore.
8. Review all conflicts/errors. Current prototype skips conflicting files and does not expose a per-file overwrite approval UI.
9. Restore and inspect all results. Reopen representative documents and verify Outlook/mailbox availability.
10. Retain source and backup until customer acceptance and job sign-off.

## Important limitations
- This prototype currently loads file data into memory during encryption/decryption, so very large profiles may exceed available RAM.
- It does not preserve ACLs, EFS semantics, alternate data streams, all timestamps, Windows registry settings, or every application profile.
- Reparse points and symlinks are intentionally skipped/rejected.
- No durable resume journal or signed report exists yet.
- Do not treat a successful hash comparison as proof that every application is correctly migrated.
