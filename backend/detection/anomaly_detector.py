"""Statistical anomaly detector using numpy and scikit-learn."""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, float] = {
    "critical": 4.0, "error": 3.0, "warning": 2.0, "info": 1.0,
}
_SOURCE_TYPE_MAP: dict[str, float] = {
    "network": 1.0, "system": 2.0, "application": 3.0,
    "api": 4.0, "file": 5.0, "stream": 6.0,
}


def extract_features(log: dict[str, Any]) -> np.ndarray:
    """Extract a fixed-length numeric feature vector from a log dict."""
    message = str(log.get("message", ""))
    raw = str(log.get("raw_log", ""))

    f: list[float] = [
        # 0: message length
        float(len(message)),
        # 1: raw log length
        float(len(raw)),
        # 2: severity score
        _SEVERITY_MAP.get(str(log.get("severity", "info")).lower(), 1.0),
        # 3: source type score
        _SOURCE_TYPE_MAP.get(str(log.get("source_type", "system")).lower(), 2.0),
        # 4: hour of day (0–23)
        float(_extract_hour(log.get("timestamp", ""))),
        # 5: has IP address
        1.0 if log.get("ip_address") else 0.0,
        # 6: has user
        1.0 if log.get("user") else 0.0,
        # 7: has process
        1.0 if log.get("process") else 0.0,
        # 8: number of parsed fields
        float(len(log.get("parsed_fields") or {})),
        # 9: number of special characters in message (proxy for obfuscation)
        float(sum(1 for c in message if c in "!@#$%^&*()[]{}|;:<>?")),
        # 10: ratio of digits in message
        float(sum(1 for c in message if c.isdigit()) / max(len(message), 1)),
        # 11: uppercase ratio in message
        float(sum(1 for c in message if c.isupper()) / max(len(message), 1)),
        # 12: event_type hash bucket (0–9)
        float(abs(hash(str(log.get("event_type", "")))) % 10),
        # 13: parsed bytes field (response size)
        float(_safe_numeric(log, "parsed_fields.bytes")),
        # 14: http status code bucket
        float(_safe_numeric(log, "parsed_fields.status_code") // 100),
    ]
    return np.array(f, dtype=np.float32)


def _extract_hour(ts: str) -> int:
    try:
        from dateutil import parser as dp
        dt = dp.parse(ts)
        return dt.hour
    except Exception:
        return datetime.now().hour


def _safe_numeric(log: dict[str, Any], dotted_key: str) -> float:
    parts = dotted_key.split(".")
    val = log
    for p in parts:
        if not isinstance(val, dict):
            return 0.0
        val = val.get(p, 0)
    try:
        return float(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


FEATURE_DIM = 15

# ---------------------------------------------------------------------------
# Per-entity baseline profile
# ---------------------------------------------------------------------------


@dataclass
class _BaselineProfile:
    key: str
    samples: list[np.ndarray] = field(default_factory=list)
    mean: np.ndarray | None = None
    std: np.ndarray | None = None
    last_updated: float = field(default_factory=time.monotonic)
    n_trained: int = 0

    MAX_SAMPLES = 500

    def add(self, features: np.ndarray) -> None:
        self.samples.append(features)
        if len(self.samples) > self.MAX_SAMPLES:
            self.samples.pop(0)
        self.last_updated = time.monotonic()

    def update_stats(self) -> None:
        if len(self.samples) < 10:
            return
        arr = np.stack(self.samples)
        self.mean = np.mean(arr, axis=0)
        self.std = np.std(arr, axis=0) + 1e-6
        self.n_trained = len(self.samples)

    def z_score_anomaly(self, features: np.ndarray) -> float:
        """Return mean absolute z-score (higher = more anomalous)."""
        if self.mean is None or len(self.samples) < 10:
            return 0.0
        z = np.abs((features - self.mean) / self.std)
        return float(np.mean(z))


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """Detect statistical anomalies in log events using Isolation Forest and z-scores.

    The detector maintains:
    * A **global** Isolation Forest trained on recent events across all sources.
    * **Per-entity baseline profiles** (keyed by ``host``, ``source``, or ``user``)
      that track rolling feature statistics for per-entity z-score analysis.

    Scores
    ------
    ``score(log)`` returns a float in [0, 1] where 1 is most anomalous.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        min_train_samples: int = 100,
        retrain_interval: int = 500,     # retrain global model every N new samples
        profile_keys: list[str] | None = None,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.min_train_samples = min_train_samples
        self.retrain_interval = retrain_interval
        self.profile_keys = profile_keys or ["host", "source", "user"]
        self.n_estimators = n_estimators
        self.random_state = random_state

        self._global_samples: deque[np.ndarray] = deque(maxlen=10_000)
        self._model: IsolationForest | None = None
        self._scaler = StandardScaler()
        self._scaler_fitted = False
        self._samples_since_retrain = 0
        self._profiles: dict[str, _BaselineProfile] = {}
        self._log = logger.bind(component="AnomalyDetector")
        self._total_scored = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, log: dict[str, Any]) -> float:
        """Return an anomaly score in [0, 1] (1 = most anomalous)."""
        features = extract_features(log)

        self._add_sample(features, log)

        scores: list[float] = []

        # Global isolation forest score
        if self._model is not None and self._scaler_fitted:
            try:
                scaled = self._scaler.transform(features.reshape(1, -1))
                raw_score = self._model.score_samples(scaled)[0]
                # Convert from [-0.5, 0] range: more negative = more anomalous
                iso_score = max(0.0, min(1.0, -raw_score * 2))
                scores.append(iso_score)
            except Exception as exc:
                self._log.debug("isolation forest score error", error=str(exc))

        # Per-entity z-score
        for pk in self.profile_keys:
            key_val = str(log.get(pk, ""))
            if not key_val:
                continue
            profile_key = f"{pk}:{key_val}"
            profile = self._profiles.get(profile_key)
            if profile and profile.n_trained >= 10:
                z = profile.z_score_anomaly(features)
                # Normalise: z > 5 → score ≈ 1
                z_norm = min(1.0, z / 5.0)
                scores.append(z_norm)

        self._total_scored += 1
        return float(np.mean(scores)) if scores else 0.0

    def fit(self, logs: list[dict[str, Any]]) -> None:
        """Train the global model on a historical log corpus."""
        if not logs:
            return
        features_list = [extract_features(l) for l in logs]
        self._train_global(features_list)
        self._log.info("anomaly detector trained", samples=len(logs))

    def incremental_update(self, log: dict[str, Any]) -> None:
        """Add a single sample and retrain if the interval threshold is reached."""
        features = extract_features(log)
        self._add_sample(features, log)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _add_sample(self, features: np.ndarray, log: dict[str, Any]) -> None:
        self._global_samples.append(features)
        self._samples_since_retrain += 1

        # Update per-entity profiles
        for pk in self.profile_keys:
            key_val = str(log.get(pk, ""))
            if not key_val:
                continue
            profile_key = f"{pk}:{key_val}"
            if profile_key not in self._profiles:
                self._profiles[profile_key] = _BaselineProfile(key=profile_key)
            self._profiles[profile_key].add(features)
            if self._samples_since_retrain % 50 == 0:
                self._profiles[profile_key].update_stats()

        # Retrain global model periodically
        if (self._samples_since_retrain >= self.retrain_interval and
                len(self._global_samples) >= self.min_train_samples):
            self._train_global(list(self._global_samples))
            self._samples_since_retrain = 0

    def _train_global(self, features_list: list[np.ndarray]) -> None:
        if len(features_list) < self.min_train_samples:
            return
        try:
            X = np.stack(features_list)
            self._scaler.fit(X)
            self._scaler_fitted = True
            X_scaled = self._scaler.transform(X)
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                n_jobs=-1,
            )
            self._model.fit(X_scaled)
            self._log.info(
                "isolation forest retrained",
                samples=len(features_list),
                features=FEATURE_DIM,
            )
        except Exception as exc:
            self._log.error("model training failed", error=str(exc))

    # ------------------------------------------------------------------
    # Event frequency analysis
    # ------------------------------------------------------------------

    def event_frequency_anomaly(
        self,
        source: str,
        event_type: str,
        window_seconds: float = 60.0,
    ) -> float:
        """Return an anomaly score based on how unusual the current event rate is.

        Maintains a rolling count per (source, event_type) pair and compares
        the current bucket against historical mean + std.
        """
        key = f"freq:{source}:{event_type}"
        now = time.monotonic()

        if not hasattr(self, "_freq_windows"):
            self._freq_windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._freq_windows[key].append(now)

        window = self._freq_windows[key]
        cutoff = now - window_seconds
        count = sum(1 for t in window if t >= cutoff)

        history_key = f"freq_hist:{source}:{event_type}"
        if not hasattr(self, "_freq_history"):
            self._freq_history: dict[str, list[int]] = defaultdict(list)
        hist = self._freq_history[history_key]
        hist.append(count)
        if len(hist) > 100:
            hist.pop(0)

        if len(hist) < 20:
            return 0.0

        mean = sum(hist) / len(hist)
        std = math.sqrt(sum((x - mean) ** 2 for x in hist) / len(hist)) + 1e-6
        z = abs(count - mean) / std
        return min(1.0, z / 5.0)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_state(self, path: str) -> None:
        """Persist model state to a JSON file (scaler params + profile stats)."""
        try:
            state: dict[str, Any] = {
                "scaler_fitted": self._scaler_fitted,
                "total_scored": self._total_scored,
                "profiles": {
                    k: {
                        "n_trained": v.n_trained,
                        "mean": v.mean.tolist() if v.mean is not None else None,
                        "std": v.std.tolist() if v.std is not None else None,
                    }
                    for k, v in self._profiles.items()
                },
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            if self._scaler_fitted:
                state["scaler_mean"] = self._scaler.mean_.tolist()
                state["scaler_scale"] = self._scaler.scale_.tolist()
            with open(path, "w") as fh:
                json.dump(state, fh, indent=2)
            self._log.info("anomaly detector state saved", path=path)
        except Exception as exc:
            self._log.error("save_state failed", error=str(exc))

    def load_state(self, path: str) -> None:
        """Restore model state from a previously saved JSON file."""
        try:
            with open(path) as fh:
                state = json.load(fh)
            if state.get("scaler_mean") and state.get("scaler_scale"):
                self._scaler.mean_ = np.array(state["scaler_mean"])
                self._scaler.scale_ = np.array(state["scaler_scale"])
                self._scaler.n_features_in_ = FEATURE_DIM
                self._scaler_fitted = True
            for k, v in state.get("profiles", {}).items():
                p = _BaselineProfile(key=k)
                p.n_trained = v.get("n_trained", 0)
                if v.get("mean"):
                    p.mean = np.array(v["mean"])
                if v.get("std"):
                    p.std = np.array(v["std"])
                self._profiles[k] = p
            self._total_scored = state.get("total_scored", 0)
            self._log.info("anomaly detector state loaded", path=path, profiles=len(self._profiles))
        except FileNotFoundError:
            self._log.info("no saved anomaly state found", path=path)
        except Exception as exc:
            self._log.error("load_state failed", error=str(exc))

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "model_trained": self._model is not None,
            "global_samples": len(self._global_samples),
            "profiles": len(self._profiles),
            "total_scored": self._total_scored,
            "contamination": self.contamination,
        }
