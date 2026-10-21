# Security

## Reporting a problem

Email security@wardlet.com with what you found. Please do not open a public
issue for a vulnerability until we have had a chance to fix it. We will
reply within a few days.

## Threat model, in one paragraph

Wardlet encrypts files with age. The master key is never written to disk;
each hardware key holds one wrapped copy, derived from the key's FIDO2
hmac-secret, so a copied disk without a hardware key cannot open the files.
The one exception is the recovery code: it is a high-entropy secret shown
once at setup, and anyone who has it can open the vault until the keys are
next changed in `wardlet config`. Protect it like a password you cannot
reset. Wardlet does not protect against malware running as your user while
a file is decrypted or being edited, and deleted plaintext originals are
removed with the normal filesystem delete, not shredded.
