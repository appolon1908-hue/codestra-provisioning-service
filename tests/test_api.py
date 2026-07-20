from fastapi.testclient import TestClient

from codestra_sip_provisioning.main import app, store


def setup_function() -> None:
    store.assignments.clear(); store.sessions.clear(); store.idempotency.clear()


def headers(key: str = "k1") -> dict[str, str]:
    return {"X-Test-Subject": "user-1", "X-Client-Instance-ID": "browser-1", "Idempotency-Key": key}


def test_health_and_config() -> None:
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/v1/sip/config").json()["live_provisioning_enabled"] is False


def test_create_replay_renew_revoke() -> None:
    client = TestClient(app)
    created = client.post("/api/v1/sip/session", headers=headers(), json={}).json()
    assert created["mock_mode"] is True and created["endpoint"].startswith("mock-")
    replay = client.post("/api/v1/sip/session", headers=headers(), json={})
    assert replay.status_code == 200 and replay.json()["session_id"] == created["session_id"]
    renewed = client.post("/api/v1/sip/session/renew", headers=headers("renew"), json={"session_id": created["session_id"]})
    assert renewed.status_code == 200 and renewed.json()["credential_rotated"] is True
    assert client.request("DELETE", "/api/v1/sip/session", headers={"X-Test-Subject": "user-1"}, json={"session_id": created["session_id"], "reason": "logout"}).status_code == 204
    assert client.request("DELETE", "/api/v1/sip/session", headers={"X-Test-Subject": "user-1"}, json={"session_id": created["session_id"], "reason": "logout"}).status_code == 204


def test_required_headers_and_one_active_session() -> None:
    client = TestClient(app)
    assert client.post("/api/v1/sip/session", headers={"X-Test-Subject": "user-1"}, json={}).status_code == 400
    assert client.post("/api/v1/sip/session", headers=headers(), json={}).status_code == 200
    assert client.post("/api/v1/sip/session", headers=headers("k2"), json={}).status_code == 409
