# SentinelMesh-XDR

SentinelMesh-XDR is a full-stack Extended Detection and Response (XDR) platform with:
- **FastAPI backend** for log ingestion, detection, correlation, incident workflows, and AI-agent orchestration
- **React frontend** for SOC-style dashboards and operations pages
- **Sample attack/log datasets** for local testing and simulation

---

## Repository Structure

```text
SentinelMesh-XDR/
├── backend/
│   ├── api/                 # FastAPI routes + dependency wiring
│   │   ├── routes/          # Feature endpoints (ingest, analyze, alerts, etc.)
│   │   └── deps.py          # Singleton service providers
│   ├── agents/              # AI/security agents and orchestrator
│   ├── correlation/         # Event correlation and attack-chain logic
│   ├── detection/           # Rule, anomaly, and threat-intel detection
│   ├── incident_response/   # Alerting, incident handling, playbooks
│   ├── ingestion/           # JSON/CSV/raw ingestion and normalization
│   ├── memory/              # Memory store and learning engine
│   ├── models/              # Pydantic/data models + DB integration
│   ├── scoring/             # Threat scoring logic
│   ├── simulation/          # Attack scenario simulators
│   ├── tests/               # Backend test suite (pytest)
│   ├── config.py            # Environment-driven app settings
│   └── main.py              # FastAPI app entrypoint
├── frontend/
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── pages/           # Route-level SOC pages
│   │   ├── store/           # Zustand state + API calls
│   │   └── test/            # Frontend tests (Jest + RTL)
│   ├── package.json         # Frontend scripts/dependencies
│   └── Dockerfile
├── sample-data/             # Example logs, anomalies, attack scenarios
├── docker-compose.yml       # Local full-stack orchestration
└── README.md
```

---

## Key Technologies

### Backend
- **Python 3 + FastAPI** for API services
- **SQLAlchemy (async)** + **SQLite/Postgres-ready configuration**
- **Pydantic v2** / `pydantic-settings` for configuration and validation
- **Redis support** for optional runtime dependencies
- **FAISS + NumPy + scikit-learn + pandas** for memory/anomaly workflows
- **Structlog** for structured logging
- **Pytest** for tests

### Frontend
- **React 19 + Vite**
- **React Router** for SPA routing
- **Zustand** for state/data fetching
- **Tailwind CSS** for styling
- **Recharts** for visual analytics
- **Jest + Testing Library** for UI tests
- **ESLint** for linting

### Deployment / Runtime
- **Docker + Docker Compose** for local multi-service setup

---

## How the Code Is Organized

### 1) API Layer (`backend/api/routes`)
Route modules are split by feature domain:
- `ingest.py`: ingest logs/batches
- `analyze.py`: analyze events for threat insights
- `alerts.py`, `incidents.py`: SOC workflow entities
- `rules.py`: detection rule management
- `simulate.py`: synthetic attack generation
- `agents.py`: agent-based analysis workflows
- `memory.py`, `correlation.py`, `monitoring.py`: memory, event-correlation, and runtime metrics

In `backend/main.py`, all routers are mounted under **`/api/v1`** (configurable via `API_PREFIX`).

### 2) Service/Engine Layer
Core detection and SOC logic is grouped by concern:
- `detection/`: rules, anomalies, threat intelligence, unified detector
- `correlation/`: relate events into sessions/chains
- `scoring/`: risk/threat score calculation
- `incident_response/`: alerting and playbook handling
- `simulation/`: brute force, SQL injection, scan, exfiltration, lateral movement simulators
- `agents/`: AI-style specialized analysis agents coordinated by `agent_orchestrator.py`

### 3) Dependency Wiring (`backend/api/deps.py`)
Shared services (rule engine, threat detector, orchestrator, memory store, etc.) are provided as singleton-style dependencies (via `@lru_cache`) for route handlers.

### 4) Frontend SPA (`frontend/src`)
- `App.jsx` defines route mapping.
- `pages/` contains SOC pages (Overview, Logs, Alerts, Incidents, Rules, Simulation, Insights).
- `components/` contains dashboard widgets/tables/layout primitives.
- `store/useAppStore.js` centralizes API calls and app state, defaulting to `VITE_API_BASE` (`http://localhost:8000/api/v1`).

---

## Local Development

### Option A: Docker Compose (full stack)
From repo root:

```bash
docker compose up --build
```

- Backend API: `http://localhost:8000`
- Frontend UI: `http://localhost:5173`
- OpenAPI docs: `http://localhost:8000/api/v1/docs`

### Option B: Run services manually

Backend:
```bash
cd backend
python -m pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:
```bash
cd frontend
npm ci
npm run dev
```

---

## Validation Commands

Backend:
```bash
cd backend
python -m pytest -q
```

Frontend:
```bash
cd frontend
npm run lint
npm test -- --runInBand
npm run build
```

---

## API Entry Points

- API root: `GET /api/v1/`
- Health: `GET /api/v1/health`
- Interactive docs: `GET /api/v1/docs`

---

## Quick Summary

This repository is organized as a modular security platform:
- **ingest + normalize logs**
- **detect + score threats**
- **correlate events**
- **manage alerts/incidents**
- **simulate attacks**
- **surface everything in a React SOC dashboard**
