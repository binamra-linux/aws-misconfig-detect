"""
Small local JSON-file persistence for scan history (data/scan_history.json,
gitignored). Single-user local tool, so a flat JSON array guarded by a
process-local lock is sufficient -- no database needed.

Records are keyed by `scanned_at` (an ISO timestamp), not the in-memory
`_scan_id` counter in api/main.py -- that counter resets to 0 on every
server restart, so it would collide across sessions in a persisted file.
"""

import json
import threading
from pathlib import Path
from typing import Any, Dict, List

_HISTORY_FILE = Path(__file__).resolve().parent.parent / "data" / "scan_history.json"
_lock = threading.Lock()


def _read_all() -> List[Dict[str, Any]]:
    if not _HISTORY_FILE.exists():
        return []
    with _HISTORY_FILE.open("r") as f:
        return json.load(f)


def _write_all(records: List[Dict[str, Any]]) -> None:
    _HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _HISTORY_FILE.open("w") as f:
        json.dump(records, f, indent=2)


def load_history() -> List[Dict[str, Any]]:
    with _lock:
        return _read_all()


def append_scan(record: Dict[str, Any]) -> None:
    with _lock:
        records = _read_all()
        records.append(record)
        _write_all(records)


def clear_history() -> None:
    with _lock:
        _write_all([])
