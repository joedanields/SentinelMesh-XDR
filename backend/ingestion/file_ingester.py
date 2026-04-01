"""File-based log ingester – watches directories and tails log files."""
from __future__ import annotations

import asyncio
import json
import os
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
import structlog

from .base_ingester import AbstractIngester, RetryConfig
from .normalizer import LogNormalizer

logger = structlog.get_logger(__name__)

SUPPORTED_EXTENSIONS = {".log", ".txt", ".json", ".csv"}

# ---------------------------------------------------------------------------
# Checkpoint – persist read positions across restarts
# ---------------------------------------------------------------------------


@dataclass
class FileCheckpoint:
    positions: dict[str, int] = field(default_factory=dict)  # path -> byte offset
    inode_map: dict[str, int] = field(default_factory=dict)   # path -> inode

    def save(self, path: str | Path) -> None:
        with open(path, "wb") as fh:
            pickle.dump(self, fh)

    @classmethod
    def load(cls, path: str | Path) -> "FileCheckpoint":
        try:
            with open(path, "rb") as fh:
                return pickle.load(fh)
        except (FileNotFoundError, EOFError, pickle.UnpicklingError):
            return cls()


# ---------------------------------------------------------------------------
# FileIngester
# ---------------------------------------------------------------------------


class FileIngester(AbstractIngester):
    """Watch one or more directories for new/updated log files and ingest them.

    Features
    --------
    * Recursively watches ``watch_dirs`` for files matching ``SUPPORTED_EXTENSIONS``.
    * Follows (tails) files – only reads new bytes appended since the last run.
    * Handles log rotation via inode tracking.
    * Saves read positions to a checkpoint file so restarts are safe.
    * Yields batches of normalised log dicts via :meth:`ingest`.
    """

    def __init__(
        self,
        source_name: str,
        watch_dirs: list[str | Path],
        batch_size: int = 500,
        follow: bool = True,
        poll_interval: float = 1.0,
        checkpoint_path: str | Path = "logs/.file_ingester_checkpoint.pkl",
        retry_config: RetryConfig | None = None,
    ) -> None:
        super().__init__(
            source_name=source_name,
            source_type="file",
            batch_size=batch_size,
            retry_config=retry_config,
        )
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.follow = follow
        self.poll_interval = poll_interval
        self.checkpoint_path = Path(checkpoint_path)
        self._normalizer = LogNormalizer(default_source=source_name, default_source_type="file")
        self._checkpoint = FileCheckpoint.load(self.checkpoint_path)
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10_000)
        self._watcher_task: asyncio.Task | None = None
        self._log = logger.bind(ingester="FileIngester", source=source_name)

    # ------------------------------------------------------------------
    # AbstractIngester interface
    # ------------------------------------------------------------------

    async def ingest(self) -> list[dict[str, Any]]:
        """Return the next batch from the internal queue."""
        batch: list[dict[str, Any]] = []
        deadline = asyncio.get_event_loop().time() + 0.5  # drain for up to 500 ms

        while len(batch) < self.batch_size:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                batch.append(item)
            except asyncio.TimeoutError:
                break
        return batch

    def validate(self, raw: dict[str, Any]) -> bool:
        return bool(raw.get("raw_log") or raw.get("line"))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        line = raw.get("line") or raw.get("raw_log", "")
        source = raw.get("source", self.source_name)
        nlog = self._normalizer.normalize(line, source=source, source_type="file")
        nlog.parsed_fields["file_path"] = raw.get("file_path", "")
        nlog.parsed_fields["line_number"] = raw.get("line_number", 0)
        return nlog.to_dict()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self._watcher_task = asyncio.create_task(self._watch_loop(), name="file_ingester_watcher")

    async def stop(self) -> None:
        if self._watcher_task:
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except asyncio.CancelledError:
                pass
        self._save_checkpoint()
        await super().stop()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _watch_loop(self) -> None:
        """Continuously scan watch dirs for new/updated files."""
        self._log.info("file watcher started", watch_dirs=[str(d) for d in self.watch_dirs])
        while self._running:
            try:
                for watch_dir in self.watch_dirs:
                    await self._scan_directory(watch_dir)
                self._save_checkpoint()
            except Exception as exc:
                self._log.error("watcher error", error=str(exc))
                self.metrics.record_error(str(exc))
            await asyncio.sleep(self.poll_interval)

    async def _scan_directory(self, directory: Path) -> None:
        if not directory.exists():
            return
        for entry in sorted(directory.rglob("*")):
            if entry.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if not entry.is_file():
                continue
            await self._process_file(entry)

    async def _process_file(self, path: Path) -> None:
        path_str = str(path)
        try:
            stat = path.stat()
            current_inode = stat.st_ino
            current_size = stat.st_size

            # Detect rotation: inode changed or file shrank
            prev_inode = self._checkpoint.inode_map.get(path_str, current_inode)
            prev_pos = self._checkpoint.positions.get(path_str, 0)

            if current_inode != prev_inode or current_size < prev_pos:
                self._log.info("file rotation detected", path=path_str)
                prev_pos = 0

            if current_size <= prev_pos:
                return  # nothing new

            self._checkpoint.inode_map[path_str] = current_inode
            encoding_errors = 0

            async with aiofiles.open(path, "r", encoding="utf-8", errors="replace") as fh:
                await fh.seek(prev_pos)
                line_number = 0
                new_pos = prev_pos

                while True:
                    line = await fh.readline()
                    if not line:
                        break
                    new_pos = await fh.tell()
                    line_number += 1
                    # Track replacement characters as a proxy for encoding errors
                    if "\ufffd" in line:
                        encoding_errors += 1
                    stripped = line.rstrip("\n\r")
                    if not stripped:
                        continue

                    raw_record = {
                        "line": stripped,
                        "file_path": path_str,
                        "line_number": line_number,
                        "source": path.stem,
                    }
                    if not self._queue.full():
                        await self._queue.put(raw_record)
                    else:
                        self._log.warning("queue full – dropping line", path=path_str)
                        self.metrics.record_error("queue full")

                if encoding_errors:
                    self._log.warning(
                        "encoding errors detected in file",
                        path=path_str,
                        replacement_chars=encoding_errors,
                        hint="file may not be UTF-8",
                    )
                self._checkpoint.positions[path_str] = new_pos

        except PermissionError:
            self._log.warning("no read permission", path=path_str)
        except Exception as exc:
            self._log.error("error processing file", path=path_str, error=str(exc))
            self.metrics.record_error(str(exc))

    def _save_checkpoint(self) -> None:
        try:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            self._checkpoint.save(self.checkpoint_path)
        except Exception as exc:
            self._log.warning("checkpoint save failed", error=str(exc))

    # ------------------------------------------------------------------
    # One-shot convenience – ingest an entire file synchronously
    # ------------------------------------------------------------------

    async def ingest_file_once(self, path: str | Path) -> list[dict[str, Any]]:
        """Read all lines from *path* and return normalised log dicts."""
        results: list[dict[str, Any]] = []
        path = Path(path)
        try:
            async with aiofiles.open(path, "r", encoding="utf-8", errors="replace") as fh:
                async for i, line in _async_enumerate(fh):
                    stripped = line.rstrip("\n\r")
                    if not stripped:
                        continue
                    raw = {"line": stripped, "file_path": str(path), "line_number": i + 1, "source": path.stem}
                    if self.validate(raw):
                        results.append(self.normalize(raw))
        except Exception as exc:
            self._log.error("ingest_file_once failed", path=str(path), error=str(exc))
        return results


async def _async_enumerate(async_iter, start: int = 0):
    i = start
    async for item in async_iter:
        yield i, item
        i += 1
