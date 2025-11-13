from fastapi.testclient import TestClient
from backend_api.api_gateway.app import app

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "PhantomNet API Running"}
