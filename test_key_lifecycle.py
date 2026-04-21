from pathlib import Path

from evidence_protector.core import (
    compute_manifest_signature,
    list_revoked_key_ids,
    revoke_key_id,
    rotate_signing_keypair,
    verify_manifest_signature,
)


def test_key_rotation_generates_new_active_key(tmp_path: Path, monkeypatch) -> None:
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("EVIDENCE_PROTECTOR_KEY_DIR", str(key_dir))
    monkeypatch.delenv("EVIDENCE_PROTECTOR_REVOKED_KEYS_PATH", raising=False)

    key_id, priv_path, pub_path = rotate_signing_keypair()

    assert key_id
    assert priv_path.exists()
    assert pub_path.exists()


def test_revoked_key_fails_signature_verification(tmp_path: Path, monkeypatch) -> None:
    key_dir = tmp_path / "keys"
    revoked_path = tmp_path / "revoked_keys.json"

    monkeypatch.setenv("EVIDENCE_PROTECTOR_KEY_DIR", str(key_dir))
    monkeypatch.setenv("EVIDENCE_PROTECTOR_REVOKED_KEYS_PATH", str(revoked_path))

    payload = {
        "manifest_version": 3,
        "file": "sample.log",
        "signed_at": "2026-01-01T00:00:00Z",
        "hash_algorithm": "sha256",
        "chain_scheme": "v1-line+prev",
        "manifest_mode": "full",
        "total_lines": 1,
        "root_hash": "abcd",
    }

    payload["signature"] = compute_manifest_signature(payload)
    key_id = str(payload["signature"].get("key_id", ""))
    assert key_id

    ok, reason = verify_manifest_signature(payload)
    assert ok is True
    assert reason == "ok"

    revoke_key_id(key_id, reason="unit-test")
    assert key_id in set(list_revoked_key_ids())

    ok, reason = verify_manifest_signature(payload)
    assert ok is False
    assert reason == "revoked-key-id"
