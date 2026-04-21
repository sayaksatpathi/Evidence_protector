# Evidence Protector Key Management

This document defines a practical lifecycle for manifest signing keys.

## 1) Active scheme

Default signing scheme is Ed25519.

Environment variables:

- `EVIDENCE_PROTECTOR_SIGNATURE_SCHEME` (`ed25519` or `hmac-sha256`)
- `EVIDENCE_PROTECTOR_KEY_DIR`
- `EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH`
- `EVIDENCE_PROTECTOR_PUBLIC_KEY_PATH`
- `EVIDENCE_PROTECTOR_ACTIVE_KEY_ID`

## 2) Storage guidance

- Store private keys outside source control.
- Restrict private key permissions to owner only (`chmod 600`).
- Treat CI, prod, and local keys as separate trust domains.
- Keep public keys/version map in a controlled artifact location.

## 3) Rotation process

1. Generate a new Ed25519 key pair in a secure environment.
2. Assign a new `key_id` and distribute the public key.
3. Set `EVIDENCE_PROTECTOR_ACTIVE_KEY_ID` and key paths to the new pair.
4. Start signing new manifests with the new key.
5. Keep old public keys available for historical verification.
6. After retention window, retire old private key material.

## 4) Backup and recovery

- Keep encrypted backups of private keys in at least two independent locations.
- Maintain offline escrow for incident recovery.
- Test restore procedures on a scheduled cadence.
- Document who can restore keys and under what approvals.

## 5) Verification policy

- Verify every artifact before evidence handoff.
- Require `manifest_signature.valid == true` for trusted signed manifests.
- Record `key_id` in case notes for chain-of-custody traceability.
- Allow legacy HMAC verification only for historical manifests and migration windows.

## 6) Legacy HMAC mode

For migration only:

- `EVIDENCE_PROTECTOR_ALLOW_LEGACY_HMAC_VERIFY`
- `EVIDENCE_PROTECTOR_SIGNING_KEY_B64`
- `EVIDENCE_PROTECTOR_SIGNING_KEY_PATH`

Do not use HMAC mode for new signed evidence if Ed25519 is available.
