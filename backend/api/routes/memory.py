"""Memory and learning engine routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.deps import get_learning_engine, get_memory_store
from memory.learning_engine import LearningEngine
from memory.memory_store import MemoryStore

router = APIRouter(prefix="/memory", tags=["Memory"])


class SimilarityRequest(BaseModel):
    query: str
    top_k: int = Field(default=5, ge=1, le=50)


@router.get("/incidents")
async def list_memory_incidents(store: MemoryStore = Depends(get_memory_store)) -> dict[str, Any]:
    items = store.get_all_memories()
    return {"items": items, "count": len(items)}


@router.post("/incidents")
async def store_incident_memory(
    payload: dict[str, Any],
    store: MemoryStore = Depends(get_memory_store),
    learner: LearningEngine = Depends(get_learning_engine),
) -> dict[str, Any]:
    if not payload:
        raise HTTPException(status_code=400, detail="incident payload is required")
    memory_id = store.store_incident(payload)
    learn_result = learner.add_incident_memory(payload)
    store.save_to_disk()
    return {"ok": True, "memory_id": memory_id, "learning": learn_result}


@router.post("/similar")
async def find_similar_incidents(
    payload: SimilarityRequest,
    store: MemoryStore = Depends(get_memory_store),
    learner: LearningEngine = Depends(get_learning_engine),
) -> dict[str, Any]:
    memory_results = store.find_similar_incidents(payload.query, payload.top_k)
    vector_results = learner.find_similar_incidents(payload.query, payload.top_k)
    return {
        "query": payload.query,
        "memory_results": memory_results,
        "vector_results": vector_results,
        "count": max(len(memory_results), len(vector_results)),
    }


@router.post("/learn/update")
async def update_learning_model(
    payload: dict[str, Any],
    learner: LearningEngine = Depends(get_learning_engine),
) -> dict[str, Any]:
    clusters = int(payload.get("clusters", 3))
    clusters = max(2, min(10, clusters))
    return learner.update_learning_model(clusters=clusters)
