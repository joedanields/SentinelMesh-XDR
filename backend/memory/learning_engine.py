"""Learning engine for SentinelMesh XDR using FAISS incident memory."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import faiss
import numpy as np
from sklearn.cluster import KMeans

from utils.logging_config import get_logger

logger = get_logger(__name__)


class LearningEngine:
    """Learns from incidents and supports similarity retrieval + clustering."""

    def __init__(self, dim: int = 256, data_dir: str = "/tmp/sentinelmesh_learning") -> None:
        self.dim = dim
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.index = faiss.IndexFlatL2(dim)
        self.memories: list[dict[str, Any]] = []
        self._load()
        logger.info("LearningEngine initialized", dim=dim, memory_count=len(self.memories))

    # --------------------------
    # Embedding
    # --------------------------

    def _embed_text(self, text: str) -> np.ndarray:
        """Deterministic hashed embedding for offline operation."""
        vec = np.zeros(self.dim, dtype=np.float32)
        for token in text.lower().split():
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            for i in range(0, len(digest), 2):
                idx = int.from_bytes(digest[i : i + 2], "big") % self.dim
                vec[idx] += 1.0
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec

    def _incident_text(self, incident: dict[str, Any]) -> str:
        fields = [
            str(incident.get("title", "")),
            str(incident.get("description", "")),
            str(incident.get("severity", "")),
            str(incident.get("status", "")),
            str(incident.get("root_cause", "")),
            " ".join(str(x) for x in incident.get("affected_hosts", []) or []),
            " ".join(str(x) for x in incident.get("alert_ids", []) or []),
        ]
        return " ".join(fields).strip()

    # --------------------------
    # Public API
    # --------------------------

    def add_incident_memory(self, incident: dict[str, Any]) -> dict[str, Any]:
        record = dict(incident)
        record.setdefault("id", str(len(self.memories) + 1))
        record["learned_at"] = datetime.now(timezone.utc).isoformat()
        text = self._incident_text(record)
        emb = self._embed_text(text)
        self.index.add(np.expand_dims(emb, axis=0))
        record["_embedding"] = emb.tolist()
        self.memories.append(record)
        self._persist()
        logger.info("Incident memory added", incident_id=record["id"])
        return {"incident_id": record["id"], "index_size": self.index.ntotal}

    def find_similar_incidents(self, query: dict[str, Any] | str, top_k: int = 5) -> list[dict[str, Any]]:
        if not self.memories or self.index.ntotal == 0:
            return []
        query_text = query if isinstance(query, str) else self._incident_text(query)
        q_emb = self._embed_text(query_text)
        distances, indices = self.index.search(np.expand_dims(q_emb, axis=0), max(1, min(top_k, len(self.memories))))
        results: list[dict[str, Any]] = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < 0 or idx >= len(self.memories):
                continue
            mem = dict(self.memories[idx])
            mem.pop("_embedding", None)
            mem["similarity"] = float(max(0.0, 1.0 - (dist / 2.0)))
            results.append(mem)
        return results

    def update_learning_model(self, clusters: int = 3) -> dict[str, Any]:
        """Run clustering and derive pattern summaries for incremental learning."""
        if len(self.memories) < 2:
            return {"updated": False, "reason": "insufficient_memories", "count": len(self.memories)}

        k = max(2, min(clusters, len(self.memories)))
        vectors = np.array([m["_embedding"] for m in self.memories], dtype=np.float32)
        model = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = model.fit_predict(vectors)

        cluster_stats: dict[int, dict[str, Any]] = {}
        for label, memory in zip(labels.tolist(), self.memories):
            info = cluster_stats.setdefault(label, {"count": 0, "severity": Counter(), "statuses": Counter()})
            info["count"] += 1
            info["severity"][str(memory.get("severity", "unknown")).lower()] += 1
            info["statuses"][str(memory.get("status", "unknown")).lower()] += 1

        patterns = []
        for label, info in cluster_stats.items():
            patterns.append(
                {
                    "cluster": int(label),
                    "count": info["count"],
                    "dominant_severity": info["severity"].most_common(1)[0][0] if info["severity"] else "unknown",
                    "dominant_status": info["statuses"].most_common(1)[0][0] if info["statuses"] else "unknown",
                }
            )

        payload = {
            "updated": True,
            "clusters": k,
            "patterns": patterns,
            "memory_count": len(self.memories),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._persist(extra={"last_model_update": payload})
        logger.info("Learning model updated", clusters=k, memory_count=len(self.memories))
        return payload

    # --------------------------
    # Persistence
    # --------------------------

    def _persist(self, extra: dict[str, Any] | None = None) -> None:
        extra = extra or {}
        safe_memories = []
        for m in self.memories:
            safe = dict(m)
            safe.pop("_embedding", None)
            safe_memories.append(safe)
        metadata = {"dim": self.dim, **extra}
        (self.data_dir / "memories.json").write_text(
            json.dumps({"memories": safe_memories, "metadata": metadata}, default=str),
            encoding="utf-8",
        )

    def _load(self) -> None:
        path = self.data_dir / "memories.json"
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            memories = payload.get("memories", [])
            for memory in memories:
                text = self._incident_text(memory)
                emb = self._embed_text(text)
                self.index.add(np.expand_dims(emb, axis=0))
                memory["_embedding"] = emb.tolist()
                self.memories.append(memory)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed loading learning data", error=str(exc))

