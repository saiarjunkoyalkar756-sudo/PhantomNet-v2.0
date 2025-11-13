import pytest
from fastapi.testclient import TestClient
from backend_api.api_gateway.app import app, get_current_user


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def authenticated_client(client):
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    return client


def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "PhantomNet API Running"}


def test_login(client):
    response = client.post("/token", data={"username": "admin", "password": "admin"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(client):
    response = client.post("/token", data={"username": "wronguser", "password": "wrongpassword"})
    assert response.status_code == 401

def test_get_logs_unauthenticated(client):
    response = client.get("/logs")
    assert response.status_code == 401

def test_get_logs_authenticated(authenticated_client):
    # Create a dummy log file
    with open("logs/attacks.log", "w") as f:
        f.write("log entry 1\n")
        f.write("log entry 2\n")
    
    response = authenticated_client.get("/logs")
    assert response.status_code == 200
    assert response.json() == {"logs": ["log entry 1", "log entry 2"]}

    # Clean up the dummy log file
    import os
    os.remove("logs/attacks.log")

def test_register_agent_bootstrap_token_reuse(client):
    # First registration with a valid token
    response = client.post("/agents/register", json={
        "public_key": "test_public_key_1",
        "role": "node",
        "version": "1.0",
        "location": "test_location",
        "bootstrap_token": "PHANTOMNET_BOOTSTRAP_TOKEN"
    })
    assert response.status_code == 200

    # Attempt to reuse the same token
    response = client.post("/agents/register", json={
        "public_key": "test_public_key_2",
        "role": "node",
        "version": "1.0",
        "location": "test_location",
        "bootstrap_token": "PHANTOMNET_BOOTSTRAP_TOKEN"
    })
    assert response.status_code == 400 # Should fail because token is already used or agent already registered with that public key
