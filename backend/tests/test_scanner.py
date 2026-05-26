import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_https_site():
    response = client.post("/api/v1/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "score" in data
    assert "checks" in data
    assert data["total_checks"] > 0


def test_scan_blocks_localhost():
    response = client.post("/api/v1/scan", json={"url": "http://localhost:8080"})
    assert response.status_code == 400


def test_scan_invalid_url():
    response = client.post("/api/v1/scan", json={"url": "not-a-url"})
    assert response.status_code == 422
