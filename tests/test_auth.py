import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth import verify_password, verify_token, generate_auth_token

@pytest.fixture(autouse=True)
def setup_test_auth():
    orig_pwd = settings.AUTH_PASSWORD
    settings.AUTH_PASSWORD = "test_secret_password"
    yield
    settings.AUTH_PASSWORD = orig_pwd

@pytest.fixture
def client():
    return TestClient(app)

def test_auth_token_logic():
    pwd = "test_secret_password"
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
    resp = client.post("/api/auth/login", json={"password": "test_secret_password"})
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

def test_rules_api_with_geosite_and_geoip(client):
    token = generate_auth_token(settings.AUTH_PASSWORD)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch rules and verify categories list
    resp = client.get("/api/rules", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "categories" in data
    assert isinstance(data["categories"], list)

    # 2. Add geosite rule
    add_resp = client.post("/api/rules/add", headers=headers, json={
        "target": "geosite:netflix",
        "action": "proxy",
        "match_type": "geosite",
        "target_type": "domain",
        "category": "流媒体服务"
    })
    assert add_resp.status_code == 200
    assert add_resp.json()["success"] is True

    # 3. Add geoip rule
    add_geoip = client.post("/api/rules/add", headers=headers, json={
        "target": "geoip:hk, geoip:mo",
        "action": "proxy",
        "match_type": "geoip",
        "target_type": "ip",
        "category": "香港 / 澳门 IP"
    })
    assert add_geoip.status_code == 200
    assert add_geoip.json()["success"] is True

    # 4. Verify they exist
    resp = client.get("/api/rules", headers=headers)
    rules = resp.json()["rules"]
    assert any("geoip:hk" in r["target"] for r in rules)
    assert any(r["target"] == "geosite:netflix" for r in rules)
    assert "流媒体服务" in resp.json()["categories"]

    # 5. Verify adding rule without category fails with 400
    bad_add = client.post("/api/rules/add", headers=headers, json={
        "target": "example.com",
        "action": "proxy",
        "category": ""
    })
    assert bad_add.status_code == 400

    # 6. Verify category reorder endpoint
    cats = resp.json().get("ordered_categories", [])
    if len(cats) >= 2:
        reversed_cats = list(reversed(cats))
        reorder_resp = client.post("/api/categories/reorder", headers=headers, json={
            "order": reversed_cats
        })
        assert reorder_resp.status_code == 200
        assert reorder_resp.json()["success"] is True
        assert reorder_resp.json()["ordered_categories"][0] == reversed_cats[0]


