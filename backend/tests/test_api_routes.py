from fastapi.testclient import TestClient

from main import app

import asyncio

from models.database import init_db

asyncio.run(init_db())

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body


def test_simulate_scenarios_endpoint():
    response = client.get("/api/v1/simulate/scenarios")
    assert response.status_code == 200
    assert "scenarios" in response.json()


def test_rules_crud_and_toggle_endpoints():
    create_payload = {
        "id": "TEST-RULE-001",
        "name": "Test Rule",
        "type": "pattern",
        "severity": "high",
        "priority": 80,
        "condition": {"field": "message", "pattern": "failed"},
        "enabled": True,
    }

    create_resp = client.post("/api/v1/rules", json=create_payload)
    assert create_resp.status_code == 200

    list_resp = client.get("/api/v1/rules")
    assert list_resp.status_code == 200
    assert any(r["id"] == "TEST-RULE-001" for r in list_resp.json()["items"])

    disable_resp = client.post("/api/v1/rules/TEST-RULE-001/disable")
    assert disable_resp.status_code == 200
    assert disable_resp.json()["enabled"] is False

    enable_resp = client.post("/api/v1/rules/TEST-RULE-001/enable")
    assert enable_resp.status_code == 200
    assert enable_resp.json()["enabled"] is True

    delete_resp = client.delete("/api/v1/rules/TEST-RULE-001")
    assert delete_resp.status_code == 200


def test_ingest_batch_and_analyze_flow():
    ingest_payload = {
        "records": [
            {
                "data": {"timestamp": "2026-04-01T00:00:00Z", "source": "test", "message": "failed password for admin", "event_type": "ssh_login_failure", "ip_address": "1.2.3.4"},
                "format": "json",
                "source": "test",
                "source_type": "system",
            },
            {
                "data": "this is a raw line",
                "format": "raw",
                "source": "raw_test",
                "source_type": "custom",
            },
        ]
    }
    ingest_resp = client.post("/api/v1/ingest/batch", json=ingest_payload)
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["accepted"] >= 2

    analyze_payload = {
        "id": "log-1",
        "timestamp": "2026-04-01T00:00:00Z",
        "source": "sshd",
        "severity": "warning",
        "message": "Failed password for root from 1.2.3.4",
        "event_type": "ssh_login_failure",
        "ip_address": "1.2.3.4",
    }
    analyze_resp = client.post("/api/v1/analyze", json=analyze_payload)
    assert analyze_resp.status_code == 200
    body = analyze_resp.json()
    assert body["ok"] is True
    assert "threat_score" in body


def test_memory_and_correlation_endpoints():
    mem_resp = client.post(
        "/api/v1/memory/incidents",
        json={"title": "Credential attack", "description": "multiple failed logins", "severity": "high"},
    )
    assert mem_resp.status_code == 200
    assert mem_resp.json()["ok"] is True

    sim_resp = client.post("/api/v1/memory/similar", json={"query": "failed logins", "top_k": 3})
    assert sim_resp.status_code == 200
    assert "memory_results" in sim_resp.json()

    corr_resp = client.post(
        "/api/v1/correlation",
        json={
            "events": [
                {
                    "id": "e1",
                    "timestamp": "2026-04-01T00:00:00Z",
                    "ip_address": "10.0.0.1",
                    "user_id": "admin",
                    "event_type": "auth_failure",
                    "raw_log": "failed password",
                },
                {
                    "id": "e2",
                    "timestamp": "2026-04-01T00:01:00Z",
                    "ip_address": "10.0.0.1",
                    "user_id": "admin",
                    "event_type": "auth_success",
                    "raw_log": "successful login",
                },
            ]
        },
    )
    assert corr_resp.status_code == 200
    assert "correlated_events" in corr_resp.json()


def test_monitoring_metrics_endpoint():
    response = client.get("/api/v1/monitoring/metrics")
    assert response.status_code == 200
    body = response.json()
    assert "database" in body
    assert "rule_engine" in body
    assert "agent_orchestrator" in body
