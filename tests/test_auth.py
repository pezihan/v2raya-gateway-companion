import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth import verify_password, verify_token, generate_auth_token

@pytest.fixture
def client():
    return TestClient(app)

def test_auth_token_logic():
    pwd = "433127"
    token = generate_auth_token(pwd)
    assert token is not None
    assert len(token) == 64  # SHA256 hex length
    assert verify_password(pwd) is True
    assert verify_password("wrong") is False
    assert verify_token(token) is True
    assert verify_token("invalid_token") is False

def test_auth_api_flow(client):
    # 1. Access protected route without token -> 401
    resp = client.get("/api/rules")
    assert resp.status_code == 401

    # 2. Check auth status
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["auth_required"] is True
    assert data["authenticated"] is False

    # 3. Login with wrong password -> 400
    resp = client.post("/api/auth/login", json={"password": "wrong_password"})
    assert resp.status_code == 400

    # 4. Login with correct password -> 200 + token
    resp = client.post("/api/auth/login", json={"password": "433127"})
    assert resp.status_code == 200
    login_data = resp.json()
    assert login_data["success"] is True
    token = login_data["token"]
    assert len(token) == 64

    # 5. Access protected route with Bearer header -> 200
    resp = client.get("/api/rules", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    # 6. Check auth status with token
    resp = client.get("/api/auth/status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["authenticated"] is True
