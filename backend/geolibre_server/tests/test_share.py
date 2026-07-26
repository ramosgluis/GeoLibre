"""Contract and security tests for the self-hosted Share service."""

from __future__ import annotations

import re

import pytest
from starlette.testclient import TestClient

from geolibre_server.app.main import app
from geolibre_server.app.share_store import ShareStore, hash_password, verify_password


@pytest.fixture()
def share_client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("GEOLIBRE_SHARE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GEOLIBRE_SHARE_PUBLIC_URL", "https://maps.example/share")
    repository = ShareStore()
    user = repository.create_user("lramos", "very-long-test-password", admin=True)
    token = repository.create_token(user["id"], "tests")
    return TestClient(app, base_url="https://testserver"), repository, token


def project_payload(visibility: str = "public") -> dict[str, str]:
    return {
        "filename": "Mapa de predios.geolibre.json",
        "content": '{"version":"1.0.0","name":"Mapa de predios","mapView":{"zoom":8}}',
        "visibility": visibility,
    }


def test_passwords_are_salted_and_verifiable() -> None:
    first = hash_password("very-long-test-password")
    second = hash_password("very-long-test-password")
    assert first != second
    assert verify_password("very-long-test-password", first)
    assert not verify_password("wrong-password", first)


def test_upload_listing_and_raw_project_contract(share_client) -> None:
    client, _, token = share_client
    unauthorized = client.post("/share/api/projects", json=project_payload())
    assert unauthorized.status_code == 401

    uploaded = client.post(
        "/share/api/projects",
        json=project_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert uploaded.status_code == 200
    project = uploaded.json()["project"]
    assert project["username"] == "lramos"
    assert project["slug"] == "mapa-de-predios"
    assert project["rawJsonUrl"] == (
        "https://maps.example/share/lramos/mapa-de-predios.geolibre.json"
    )
    assert project["viewerUrl"].startswith("https://maps.example/?url=")

    listing = client.get("/share/api/projects").json()["projects"]
    assert [item["id"] for item in listing] == [project["id"]]

    raw = client.get("/share/lramos/mapa-de-predios.geolibre.json")
    assert raw.status_code == 200
    assert raw.json()["name"] == "Mapa de predios"
    assert raw.headers["access-control-allow-origin"] == "*"


def test_private_project_requires_owner_token(share_client) -> None:
    client, _, token = share_client
    uploaded = client.post(
        "/share/api/projects",
        json=project_payload("private"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert uploaded.status_code == 200
    assert client.get("/share/api/projects").json()["projects"] == []
    raw_url = "/share/lramos/mapa-de-predios.geolibre.json"
    assert client.get(raw_url).status_code == 401
    assert (
        client.get(raw_url, headers={"Authorization": f"Bearer {token}"}).status_code == 200
    )

    me = client.get(
        "/share/api/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert me.json() == {"user": {"username": "lramos"}}
    mine = client.get(
        "/share/api/users/lramos/projects",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert mine.json()["projects"][0]["visibility"] == "private"


def test_rejects_malformed_project(share_client) -> None:
    client, _, token = share_client
    response = client.post(
        "/share/api/projects",
        json={"filename": "bad.json", "content": "{}", "visibility": "public"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert "Invalid" in response.json()["error"]


def test_rejects_request_over_configured_share_limit(
    share_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from geolibre_server.app import share

    client, _, token = share_client
    monkeypatch.setattr(share, "MAX_PROJECT_BYTES", 8)
    response = client.post(
        "/share/api/projects",
        json=project_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 413


def test_portal_login_csrf_and_one_time_token(share_client) -> None:
    client, _, _ = share_client
    logged_in = client.post(
        "/share/login",
        data={"username": "lramos", "password": "very-long-test-password"},
        follow_redirects=False,
    )
    assert logged_in.status_code == 303
    assert "HttpOnly" in logged_in.headers["set-cookie"]
    assert "Secure" in logged_in.headers["set-cookie"]

    settings = client.get("/share/settings")
    assert settings.status_code == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', settings.text)
    assert csrf
    assert client.post("/share/tokens", data={"name": "bad"}).status_code == 403

    created = client.post(
        "/share/tokens", data={"name": "browser", "csrf": csrf.group(1)}
    )
    assert created.status_code == 200
    assert re.search(r"glb_[A-Za-z0-9_-]+", created.text)
    assert "glb_" not in created.headers.get("location", "")
