import io
import json
import time
import zipfile
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile

import evidence_protector_api as api


client = TestClient(api.app)


def _sample_log_bytes(suffix: str = "") -> bytes:
    return (
        "2026-01-15T14:00:00Z ok\n"
        "2026-01-15T14:00:01Z ok\n"
        f"2026-01-15T14:00:02Z {suffix or 'ok'}\n"
    ).encode("utf-8")


def _sign(log_bytes: bytes, *, idempotency_key: str | None = None):
    headers = {}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    return client.post(
        "/api/sign",
        files={"file": ("sample.log", log_bytes, "text/plain")},
        data={"manifest_mode": "full", "checkpoint_every": "1000", "chain_scheme": "v1"},
        headers=headers,
    )


def _verify(log_bytes: bytes, manifest_obj: dict, *, idempotency_key: str | None = None):
    headers = {}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    return client.post(
        "/api/verify",
        files={
            "file": ("sample.log", log_bytes, "text/plain"),
            "manifest": ("sample.manifest.json", json.dumps(manifest_obj).encode("utf-8"), "application/json"),
        },
        headers=headers,
    )


def test_openapi_contains_core_paths_and_multipart_contract() -> None:
    res = client.get("/openapi.json")
    assert res.status_code == 200
    spec = res.json()

    required_paths = {
        "/api/health",
        "/api/scan",
        "/api/sign",
        "/api/verify",
        "/api/jobs/scan",
        "/api/jobs/{job_id}",
        "/api/ghost/baseline",
        "/api/ghost/analyze",
        "/api/ghost/receipts",
        "/api/ghost/correlate",
    }

    for path in required_paths:
        assert path in spec.get("paths", {}), f"Missing OpenAPI path: {path}"

    sign_req = spec["paths"]["/api/sign"]["post"]["requestBody"]["content"]
    verify_req = spec["paths"]["/api/verify"]["post"]["requestBody"]["content"]
    assert "multipart/form-data" in sign_req
    assert "multipart/form-data" in verify_req


def test_sign_rejects_non_multipart_content_type() -> None:
    res = client.post("/api/sign", json={"file": "not-a-file"})
    assert res.status_code == 415
    payload = res.json()
    assert payload.get("ok") is False
    assert payload.get("error_code") == "unsupported_content_type"


def test_sign_idempotency_replay_and_conflict() -> None:
    key = "sign-key-1"

    first = _sign(_sample_log_bytes("ok"), idempotency_key=key)
    assert first.status_code == 200
    first_json = first.json()
    assert first_json["ok"] is True

    replay = _sign(_sample_log_bytes("ok"), idempotency_key=key)
    assert replay.status_code == 200
    replay_json = replay.json()
    assert replay_json["root_hash"] == first_json["root_hash"]
    assert replay_json["manifest"]["root_hash"] == first_json["manifest"]["root_hash"]

    conflict = _sign(_sample_log_bytes("changed"), idempotency_key=key)
    assert conflict.status_code == 409
    conflict_json = conflict.json()
    assert conflict_json.get("error_code") == "idempotency_conflict"


def test_verify_idempotency_replay_and_conflict() -> None:
    log_bytes = _sample_log_bytes("for-verify")
    sign_res = _sign(log_bytes)
    assert sign_res.status_code == 200
    manifest = sign_res.json()["manifest"]

    key = "verify-key-1"

    first = _verify(log_bytes, manifest, idempotency_key=key)
    assert first.status_code == 200
    first_json = first.json()
    assert first_json["ok"] is True

    replay = _verify(log_bytes, manifest, idempotency_key=key)
    assert replay.status_code == 200
    replay_json = replay.json()
    assert replay_json["status"] == first_json["status"]
    assert replay_json["report"]["clean"] == first_json["report"]["clean"]

    conflict = _verify(_sample_log_bytes("tampered"), manifest, idempotency_key=key)
    assert conflict.status_code == 409
    conflict_json = conflict.json()
    assert conflict_json.get("error_code") == "idempotency_conflict"


def test_jobs_scan_rejects_non_multipart_content_type() -> None:
    res = client.post("/api/jobs/scan", json={"file": "not-a-file"})
    assert res.status_code == 415
    assert res.json().get("error_code") == "unsupported_content_type"


def test_jobs_scan_lifecycle_succeeds() -> None:
    enqueue = client.post(
        "/api/jobs/scan",
        files={"file": ("sample.log", _sample_log_bytes("job"), "text/plain")},
        data={"gap": "300", "output_format": "json"},
    )
    assert enqueue.status_code == 202
    payload = enqueue.json()
    assert payload.get("ok") is True
    job_id = payload.get("job_id")
    assert isinstance(job_id, str) and job_id

    final = None
    for _ in range(40):
        status_res = client.get(f"/api/jobs/{job_id}")
        assert status_res.status_code == 200
        status_payload = status_res.json()
        assert status_payload.get("ok") is True
        if status_payload.get("status") in {"succeeded", "failed"}:
            final = status_payload
            break
        time.sleep(0.05)

    assert final is not None
    assert final.get("status") == "succeeded"
    result = final.get("result")
    assert isinstance(result, dict)
    assert result.get("mode") == "scan"


def test_temp_upload_encryption_writes_ciphertext(monkeypatch, tmp_path: Path) -> None:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    monkeypatch.setattr(api, "TEMP_ENCRYPTION_KEY_B64", key.decode("utf-8"))
    monkeypatch.setattr(api, "_fernet", None)

    destination = tmp_path / "upload.bin"
    payload = _sample_log_bytes("encrypted")
    upload = UploadFile(filename="sample.log", file=io.BytesIO(payload))

    received, sha256 = api._save_upload_with_sha256(upload, destination, max_bytes=10_000)
    assert received == len(payload)
    assert isinstance(sha256, str) and len(sha256) == 64

    stored = destination.read_bytes()
    assert stored != payload

    decrypted = fernet.decrypt(stored)
    assert decrypted == payload


def test_prune_finished_jobs_removes_expired() -> None:
    now = time.time()
    old_epoch = now - (api.JOB_RECORD_RETENTION_SECONDS + 5)

    with api._job_lock:
        api._jobs.clear()
        api._jobs["old_job"] = {
            "job_id": "old_job",
            "status": "succeeded",
            "finished_at_epoch": old_epoch,
        }
        api._jobs["fresh_job"] = {
            "job_id": "fresh_job",
            "status": "succeeded",
            "finished_at_epoch": now,
        }

    api._prune_finished_jobs(now_epoch=now)

    with api._job_lock:
        assert "old_job" not in api._jobs
        assert "fresh_job" in api._jobs


def test_ghost_analyze_rejects_invalid_drift_profile() -> None:
    res = client.post(
        "/api/ghost/analyze",
        files={"file": ("sample.log", _sample_log_bytes("ghost"), "text/plain")},
        data={"drift_profile": "aggressive"},
    )
    assert res.status_code == 400
    payload = res.json()
    assert payload.get("error_code") == "invalid_drift_profile"


def test_ghost_analyze_accepts_named_drift_profile_defaults() -> None:
    res = client.post(
        "/api/ghost/analyze",
        files={"file": ("sample.log", _sample_log_bytes("ghost"), "text/plain")},
        data={"drift_profile": "strict"},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload.get("ok") is True
    config = payload.get("report", {}).get("config", {})
    assert config.get("drift_profile") == "strict"
    assert config.get("gap_threshold_seconds") == 180
    assert config.get("window_lines") == 150


def test_ghost_analyze_drift_window_controls_override_profile_defaults() -> None:
    res = client.post(
        "/api/ghost/analyze",
        files={"file": ("sample.log", _sample_log_bytes("ghost"), "text/plain")},
        data={
            "drift_profile": "lenient",
            "drift_window_lines": "111",
            "drift_min_window_chars": "222",
        },
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload.get("ok") is True
    config = payload.get("report", {}).get("config", {})
    assert config.get("drift_profile") == "lenient"
    assert config.get("window_lines") == 111
    assert config.get("dna_min_window_chars") == 222
    assert config.get("entropy_min_window_chars") == 222


def test_case_package_export_contains_expected_files() -> None:
    sign_res = _sign(_sample_log_bytes("case-package"))
    assert sign_res.status_code == 200
    manifest_obj = sign_res.json()["manifest"]

    tamper_report = {
        "clean": False,
        "issues_found": 1,
        "issues": [{"line_number": 2, "status": "TAMPERED"}],
    }
    ghost_report = {
        "events": [{"signal_type": "rhythm", "severity": "high"}],
        "summary": {"drift_events": 1},
    }

    case_res = client.post(
        "/api/case-package",
        files={
            "file": ("sample.log", _sample_log_bytes("case-package"), "text/plain"),
            "manifest": ("sample.manifest.json", json.dumps(manifest_obj).encode("utf-8"), "application/json"),
            "tamper_report": ("tamper_report.json", json.dumps(tamper_report).encode("utf-8"), "application/json"),
            "ghost_report": ("ghost_report.json", json.dumps(ghost_report).encode("utf-8"), "application/json"),
        },
    )
    assert case_res.status_code == 200
    assert case_res.headers.get("content-type") == "application/zip"
    content_disposition = case_res.headers.get("content-disposition", "")
    assert "attachment; filename=case_" in content_disposition

    zip_bytes = io.BytesIO(case_res.content)
    with zipfile.ZipFile(zip_bytes, "r") as zf:
        names = set(zf.namelist())
        assert "evidence/sample.log" in names
        assert "evidence/manifest.json" in names
        assert "evidence/tamper_report.json" in names
        assert "evidence/ghost_report.json" in names
        assert "case_metadata.json" in names
        assert "README.txt" in names

        metadata = json.loads(zf.read("case_metadata.json").decode("utf-8"))
        assert metadata["file_name"] == "sample.log"
        assert metadata["tampering_detected"] is True
        assert metadata["root_hash"] == manifest_obj.get("root_hash", "")
        assert metadata["fingerprint_phrase"] == manifest_obj.get("fingerprint_phrase", "")
        assert len(metadata["evidence_files"]) >= 4


def test_case_package_export_requires_manifest() -> None:
    case_res = client.post(
        "/api/case-package",
        files={
            "file": ("sample.log", _sample_log_bytes("case-package"), "text/plain"),
        },
    )
    assert case_res.status_code == 422


def test_split_health_endpoints_return_ok() -> None:
    for path in ("/api/health", "/api/health/live", "/api/health/ready"):
        res = client.get(path)
        assert res.status_code == 200
        payload = res.json()
        assert payload.get("status") == "ok"
        assert isinstance(payload.get("request_id"), str)


def test_audit_endpoint_returns_events() -> None:
    client.get("/api/health")
    client.get("/api/health/live")

    res = client.get("/api/audit?limit=10")
    assert res.status_code == 200
    payload = res.json()
    assert payload.get("ok") is True
    assert payload.get("mode") == "audit-list"
    assert isinstance(payload.get("events"), list)
    if payload.get("events"):
        first = payload["events"][0]
        assert "trace_id" in first
        assert "api_role" in first


def test_rbac_role_permissions(monkeypatch) -> None:
    monkeypatch.setattr(api, "API_ROLE_BY_KEY", {"viewer-key": "viewer", "analyst-key": "analyst"})
    monkeypatch.setattr(api, "API_KEY", "")

    viewer_health = client.get("/api/health", headers={"X-API-Key": "viewer-key"})
    assert viewer_health.status_code == 200

    viewer_scan = client.post(
        "/api/scan",
        files={"file": ("sample.log", _sample_log_bytes("rbac"), "text/plain")},
        headers={"X-API-Key": "viewer-key"},
    )
    assert viewer_scan.status_code == 403

    analyst_scan = client.post(
        "/api/scan",
        files={"file": ("sample.log", _sample_log_bytes("rbac"), "text/plain")},
        headers={"X-API-Key": "analyst-key"},
    )
    assert analyst_scan.status_code == 200

