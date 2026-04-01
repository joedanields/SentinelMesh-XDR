"""SentinelMesh XDR – In-memory + disk-persisted incident/pattern store with TF-IDF similarity."""
from __future__ import annotations

import json
import math
import re
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from utils.logging_config import get_logger

logger = get_logger(__name__)


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z0-9]+", text.lower())


def _tfidf_vector(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    tf = Counter(tokens)
    total = max(len(tokens), 1)
    return {t: (count / total) * idf.get(t, 1.0) for t, count in tf.items()}


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    common = set(a) & set(b)
    if not common:
        return 0.0
    dot = sum(a[k] * b[k] for k in common)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


class MemoryStore:
    """Persistent memory store for incidents, patterns, and detection results."""

    MAX_ENTRIES = 10_000

    def __init__(self, data_dir: str = "/tmp/sentinelmesh_memory") -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._incidents: dict[str, dict[str, Any]] = {}
        self._patterns: list[dict[str, Any]] = []
        self._doc_freq: Counter[str] = Counter()
        self._idf: dict[str, float] = {}
        self.load_from_disk()
        logger.info("MemoryStore initialised", data_dir=str(self._data_dir))

    # ------------------------------------------------------------------
    # IDF helpers
    # ------------------------------------------------------------------

    def _rebuild_idf(self) -> None:
        N = max(len(self._incidents), 1)
        self._idf = {
            term: math.log((N + 1) / (freq + 1)) + 1
            for term, freq in self._doc_freq.items()
        }

    def _index_text(self, text: str) -> None:
        tokens = set(_tokenize(text))
        for t in tokens:
            self._doc_freq[t] += 1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store_incident(self, incident: dict[str, Any]) -> str:
        memory_id = incident.get("id") or str(uuid.uuid4())
        incident["memory_id"] = memory_id
        incident["stored_at"] = time.time()

        text = " ".join(
            str(incident.get(k, ""))
            for k in ("title", "description", "root_cause", "lessons_learned", "severity")
        )
        self._index_text(text)
        incident["_text"] = text

        self._incidents[memory_id] = incident
        self._rebuild_idf()
        self._prune()
        logger.debug("Incident stored in memory", memory_id=memory_id)
        return memory_id

    def find_similar_incidents(self, query_text: str, top_k: int = 5) -> list[dict[str, Any]]:
        if not self._incidents:
            return []
        q_tokens = _tokenize(query_text)
        q_vec = _tfidf_vector(q_tokens, self._idf)
        scored: list[tuple[float, dict[str, Any]]] = []
        for entry in self._incidents.values():
            d_vec = _tfidf_vector(_tokenize(entry.get("_text", "")), self._idf)
            score = _cosine(q_vec, d_vec)
            scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_k]]

    def store_pattern(self, pattern: dict[str, Any]) -> str:
        pattern_id = str(uuid.uuid4())
        pattern["pattern_id"] = pattern_id
        pattern["stored_at"] = time.time()
        self._patterns.append(pattern)
        return pattern_id

    def get_attack_patterns(self) -> list[dict[str, Any]]:
        return list(self._patterns)

    def get_all_memories(self) -> list[dict[str, Any]]:
        return [
            {k: v for k, v in inc.items() if not k.startswith("_")}
            for inc in self._incidents.values()
        ]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_to_disk(self) -> None:
        try:
            incidents_path = self._data_dir / "incidents.json"
            patterns_path = self._data_dir / "patterns.json"
            safe_incidents = {
                mid: {k: v for k, v in inc.items() if not k.startswith("_")}
                for mid, inc in self._incidents.items()
            }
            incidents_path.write_text(json.dumps(safe_incidents, default=str), encoding="utf-8")
            patterns_path.write_text(json.dumps(self._patterns, default=str), encoding="utf-8")
            logger.debug("MemoryStore saved to disk")
        except Exception as exc:
            logger.error("Failed to save MemoryStore", error=str(exc))

    def load_from_disk(self) -> None:
        try:
            incidents_path = self._data_dir / "incidents.json"
            if incidents_path.exists():
                data = json.loads(incidents_path.read_text(encoding="utf-8"))
                for mid, inc in data.items():
                    text = " ".join(str(inc.get(k, "")) for k in ("title", "description", "root_cause", "severity"))
                    inc["_text"] = text
                    self._incidents[mid] = inc
                    self._index_text(text)
                self._rebuild_idf()

            patterns_path = self._data_dir / "patterns.json"
            if patterns_path.exists():
                self._patterns = json.loads(patterns_path.read_text(encoding="utf-8"))
            logger.info("MemoryStore loaded from disk", incidents=len(self._incidents), patterns=len(self._patterns))
        except Exception as exc:
            logger.warning("Could not load MemoryStore from disk", error=str(exc))

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    def _prune(self) -> None:
        if len(self._incidents) <= self.MAX_ENTRIES:
            return
        sorted_ids = sorted(self._incidents, key=lambda mid: self._incidents[mid].get("stored_at", 0))
        to_remove = sorted_ids[: len(self._incidents) - self.MAX_ENTRIES]
        for mid in to_remove:
            self._incidents.pop(mid, None)
        logger.debug("Pruned memory store", removed=len(to_remove))
