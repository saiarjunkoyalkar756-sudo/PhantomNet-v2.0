from fastapi.testclient import TestClient
from backend_api.api_gateway.app import app, get_db
from backend_api.database import SessionLocal, create_db_and_tables, User, Base, engine
from backend_api.auth import get_password_hash
import pytest

client = TestClient(app)

# Override the get_db dependency for testing
@pytest.fixture(name="session")
def session_fixture():
    # Create a new database for each test case
    Base.metadata.drop_all(bind=engine)  # Drop existing tables
    create_db_and_tables()  # Create tables
    db = SessionLocal()
    yield db
    db.close()

@pytest.fixture(name="client_with_db")
def client_with_db_fixture(session):
    app.dependency_overrides[get_db] = lambda: session
    yield client
    app.dependency_overrides.clear()

def test_register_user(client_with_db):
    response = client_with_db.post(
        "/register",
        json={
            "username": "testuser",
            "password": "testpassword",
            "role": "user"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert "hashed_password" in data
    assert data["role"] == "user"

def test_register_existing_user(client_with_db):
    client_with_db.post(
        "/register",
        json={
            "username": "testuser",
            "password": "testpassword",
            "role": "user"
        }
    )
    response = client_with_db.post(
        "/register",
        json={
            "username": "testuser",
            "password": "anotherpassword",
            "role": "user"
        }
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already registered"}

def test_login_for_access_token(client_with_db):
    # Register a user first
    client_with_db.post(
        "/register",
        json={
            "username": "testuser",
            "password": "testpassword",
            "role": "user"
        }
    )

    response = client_with_db.post(
        "/token",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_for_access_token_invalid_credentials(client_with_db):
    response = client_with_db.post(
        "/token",
        data={
            "username": "nonexistent",
            "password": "wrongpassword"
        }
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}

def test_read_users_me(client_with_db):
    # Register and login a user
    client_with_db.post(
        "/register",
        json={
            "username": "testuser",
            "password": "testpassword",
            "role": "user"
        }
    )
    login_response = client_with_db.post(
        "/token",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    token = login_response.json()["access_token"]

    response = client_with_db.get(
        "/users/me/",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["role"] == "user"

def test_read_users_me_unauthorized(client_with_db):
    response = client_with_db.get(
        "/users/me/"
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}

def test_role_based_access_admin(client_with_db):
    # Register an admin user
    client_with_db.post(
        "/register",
        json={
            "username": "adminuser",
            "password": "adminpassword",
            "role": "admin"
        }
    )
    login_response = client_with_db.post(
        "/token",
        data={
            "username": "adminuser",
            "password": "adminpassword"
        }
    )
    admin_token = login_response.json()["access_token"]

    # Attempt to access an admin-only endpoint (e.g., /blockchain/add_transaction)
    # This endpoint requires a TransactionData payload, so we'll mock it.
    # For simplicity, we'll just check the status code for authorization.
    response = client_with_db.post(
        "/blockchain/add_transaction",
        headers={
            "Authorization": f"Bearer {admin_token}"
        },
        json={
            "ip": "192.168.1.1",
            "port": 80,
            "data": "test data"
        }
    )
    # Expect 422 Unprocessable Entity because TransactionData is not fully mocked, but not 403 Forbidden
    assert response.status_code != 403

def test_role_based_access_non_admin(client_with_db):
    # Register a regular user
    client_with_db.post(
        "/register",
        json={
            "username": "regularuser",
            "password": "regularpassword",
            "role": "user"
        }
    )
    login_response = client_with_db.post(
        "/token",
        data={
            "username": "regularuser",
            "password": "regularpassword"
        }
    )
    user_token = login_response.json()["access_token"]

    # Attempt to access an admin-only endpoint
    response = client_with_db.post(
        "/blockchain/add_transaction",
        headers={
            "Authorization": f"Bearer {user_token}"
        },
        json={
            "ip": "192.168.1.1",
            "port": 80,
            "data": "test data"
        }
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Not enough permissions"}
