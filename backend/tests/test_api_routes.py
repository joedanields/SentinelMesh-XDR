from fastapi.testclient import TestClient

from main import app


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body


def test_simulate_scenarios_endpoint():
    client = TestClient(app)
    response = client.get("/api/v1/simulate/scenarios")
    assert response.status_code == 200
    assert "scenarios" in response.json()
