"""Rule management API routes."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from api.deps import get_rule_engine
from detection.rule_engine import RuleEngine

router = APIRouter(prefix="/rules", tags=["Rules"])


class RuleCreateRequest(BaseModel):
    id: str = Field(..., min_length=3, max_length=100)
    name: str = Field(..., min_length=3, max_length=255)
    type: Literal["signature", "pattern", "regex", "threshold", "statistical"] = "signature"
    severity: str = Field(default="medium", max_length=50)
    priority: int = Field(default=50, ge=1, le=100)
    condition: dict[str, Any]
    description: str = ""
    mitre_technique: str = ""
    enabled: bool = True

    @field_validator("condition")
    @classmethod
    def validate_condition(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not v:
            raise ValueError("condition must not be empty")
        return v


@router.get("")
async def list_rules(engine: RuleEngine = Depends(get_rule_engine)) -> dict[str, Any]:
    return {
        "items": engine.list_rules(),
        "count": len(engine.list_rules()),
        "performance": engine.performance_stats(),
    }


@router.post("")
async def create_rule(payload: RuleCreateRequest, engine: RuleEngine = Depends(get_rule_engine)) -> dict[str, Any]:
    rule_type = "pattern" if payload.type == "regex" else payload.type
    try:
        rule = engine.add_rule_from_dict(
            {
                "id": payload.id,
                "name": payload.name,
                "type": rule_type,
                "severity": payload.severity,
                "priority": payload.priority,
                "condition": payload.condition,
                "description": payload.description,
                "mitre_technique": payload.mitre_technique,
                "enabled": payload.enabled,
            }
        )
        return {
            "ok": True,
            "rule": {
                "id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "priority": rule.priority,
                "enabled": rule.enabled,
                "type": rule.__class__.__name__,
            },
        }
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid rule definition: {type(exc).__name__}") from exc


@router.post("/{rule_id}/enable")
async def enable_rule(rule_id: str, engine: RuleEngine = Depends(get_rule_engine)) -> dict[str, Any]:
    if rule_id not in {r["id"] for r in engine.list_rules()}:
        raise HTTPException(status_code=404, detail="Rule not found")
    engine.enable_rule(rule_id)
    return {"ok": True, "rule_id": rule_id, "enabled": True}


@router.post("/{rule_id}/disable")
async def disable_rule(rule_id: str, engine: RuleEngine = Depends(get_rule_engine)) -> dict[str, Any]:
    if rule_id not in {r["id"] for r in engine.list_rules()}:
        raise HTTPException(status_code=404, detail="Rule not found")
    engine.disable_rule(rule_id)
    return {"ok": True, "rule_id": rule_id, "enabled": False}


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, engine: RuleEngine = Depends(get_rule_engine)) -> dict[str, Any]:
    removed = engine.remove_rule(rule_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"ok": True, "rule_id": rule_id}
