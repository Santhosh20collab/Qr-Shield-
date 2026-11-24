"""Local SQLite scan history and dashboard statistics.

History stays on the machine and can be cleared from the CLI
(``qrshield history --clear``) or the web UI. Every write is a short
transaction, so the database is safe for concurrent requests.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

PathLike = Union[str, Path]

MAX_PAYLOAD_STORED = 2048
MAX_REASONS_STORED = 20

_LOCK = threading.Lock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT    NOT NULL,
    source        TEXT    NOT NULL DEFAULT 'url',
    filename      TEXT,
    payload       TEXT    NOT NULL DEFAULT '',
    payload_type  TEXT,
    url           TEXT,
    host          TEXT,
    verdict       TEXT    NOT NULL,
    score         REAL    NOT NULL DEFAULT 0,
    probability   REAL,
    decode_method TEXT,
    reasons       TEXT,
    result_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _db_path(path: Optional[PathLike] = None) -> Path:
    if path is not None:
        return Path(path)
    from . import config

    return Path(config.HISTORY_DB_PATH)


@contextmanager
def _session(path: Optional[PathLike] = None) -> Iterator[sqlite3.Connection]:
    db = _db_path(path)
    db.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        conn = sqlite3.connect(str(db), timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db(path: Optional[PathLike] = None) -> None:
    with _session(path):
        pass


def _extract(result: Dict[str, Any], source: str, filename: Optional[str]) -> Dict[str, Any]:
    info = result.get("url_info") or {}
    reasons = (result.get("reasons") or [])[:MAX_REASONS_STORED]
    model = result.get("model") or {}
    compact_reasons = [
        {
            "code": r.get("code"),
            "severity": r.get("severity"),
            "message": r.get("message"),
        }
        for r in reasons
    ]
    return {
        "created_at": _now(),
        "source": source,
        "filename": filename,
        "payload": (result.get("payload") or "")[:MAX_PAYLOAD_STORED],
        "payload_type": result.get("payload_type"),
        "url": result.get("url"),
        "host": info.get("host"),
        "verdict": result.get("verdict") or "unknown",
        "score": float(result.get("score") or 0.0),
        "probability": result.get("probability"),
        "decode_method": result.get("decode_method"),
        "reasons": json.dumps(compact_reasons, ensure_ascii=False),
        "result_json": json.dumps(
            {
                "result": result,
                "model_probability": model.get("probability"),
                "model_used": model.get("used", False),
                "filename": filename,
                "source": source,
            },
            ensure_ascii=False,
            default=str,
        ),
    }


def record_scan(
    result: Dict[str, Any],
    source: str = "url",
    filename: Optional[str] = None,
    path: Optional[PathLike] = None,
) -> int:
    """Persist one analysis result and return the new row id."""
    row = _extract(result, source, filename)
    columns = ", ".join(row)
    placeholders = ", ".join("?" for _ in row)
    with _session(path) as conn:
        cursor = conn.execute(
            f"INSERT INTO scans ({columns}) VALUES ({placeholders})",
            tuple(row.values()),
        )
        return int(cursor.lastrowid)


def _summary(row: sqlite3.Row) -> Dict[str, Any]:
    data = dict(row)
    data.pop("result_json", None)
    try:
        data["reasons"] = json.loads(data.get("reasons") or "[]")
    except (TypeError, ValueError):
        data["reasons"] = []
    return data


def list_scans(
    limit: int = 50,
    offset: int = 0,
    verdict: Optional[str] = None,
    query: Optional[str] = None,
    path: Optional[PathLike] = None,
) -> Dict[str, Any]:
    """Return a page of history summaries, newest first."""
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    where: List[str] = []
    params: List[Any] = []
    if verdict:
        where.append("verdict = ?")
        params.append(verdict)
    if query:
        where.append("(payload LIKE ? OR host LIKE ? OR filename LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like, like])
    clause = f" WHERE {' AND '.join(where)}" if where else ""

    with _session(path) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM scans{clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM scans{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "items": [_summary(row) for row in rows],
    }


def get_scan(scan_id: int, path: Optional[PathLike] = None) -> Optional[Dict[str, Any]]:
    with _session(path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
    if row is None:
        return None
    data = _summary(row)
    try:
        data["detail"] = json.loads(row["result_json"] or "{}")
    except (TypeError, ValueError):
        data["detail"] = {}
    return data


def delete_scan(scan_id: int, path: Optional[PathLike] = None) -> bool:
    with _session(path) as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (int(scan_id),))
        return cursor.rowcount > 0


def clear_history(path: Optional[PathLike] = None) -> int:
    with _session(path) as conn:
        cursor = conn.execute("DELETE FROM scans")
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
        except sqlite3.OperationalError:
            pass
        return int(cursor.rowcount)


def stats(path: Optional[PathLike] = None) -> Dict[str, Any]:
    """Aggregate counts used by the dashboard."""
    today = datetime.now(timezone.utc).date()
    week_start = today - timedelta(days=6)
    with _session(path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_verdict = {
            row["verdict"]: int(row["n"])
            for row in conn.execute(
                "SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict"
            ).fetchall()
        }
        avg_score = conn.execute("SELECT AVG(score) FROM scans").fetchone()[0] or 0.0
        today_count = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE substr(created_at, 1, 10) = ?",
            (today.isoformat(),),
        ).fetchone()[0]
        daily_rows = conn.execute(
            "SELECT substr(created_at, 1, 10) AS day, verdict, COUNT(*) AS n "
            "FROM scans WHERE substr(created_at, 1, 10) >= ? "
            "GROUP BY day, verdict ORDER BY day",
            (week_start.isoformat(),),
        ).fetchall()
        reason_rows = conn.execute(
            "SELECT reasons FROM scans ORDER BY id DESC LIMIT 500"
        ).fetchall()
        host_rows = conn.execute(
            "SELECT host, COUNT(*) AS n, "
            "SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END) AS bad "
            "FROM scans WHERE host IS NOT NULL AND host != '' "
            "GROUP BY host ORDER BY n DESC LIMIT 5"
        ).fetchall()

    daily: Dict[str, Dict[str, int]] = {}
    for offset in range(7):
        day = (week_start + timedelta(days=offset)).isoformat()
        daily[day] = {"total": 0, "malicious": 0, "suspicious": 0, "safe": 0}
    for row in daily_rows:
        bucket = daily.setdefault(
            row["day"], {"total": 0, "malicious": 0, "suspicious": 0, "safe": 0}
        )
        bucket["total"] += int(row["n"])
        verdict = row["verdict"]
        if verdict in bucket:
            bucket[verdict] += int(row["n"])

    reason_counts: Dict[str, int] = {}
    for row in reason_rows:
        try:
            items = json.loads(row["reasons"] or "[]")
        except (TypeError, ValueError):
            continue
        for item in items:
            code = item.get("code")
            if not code or item.get("severity") in ("positive", "info"):
                continue
            reason_counts[code] = reason_counts.get(code, 0) + 1

    total_int = int(total)
    malicious = by_verdict.get("malicious", 0)
    return {
        "total": total_int,
        "today": int(today_count),
        "by_verdict": by_verdict,
        "malicious_rate": round(malicious / total_int, 4) if total_int else 0.0,
        "average_score": round(float(avg_score), 1),
        "last_7_days": [{"date": day, **values} for day, values in daily.items()],
        "top_reasons": [
            {"code": code, "count": count}
            for code, count in sorted(
                reason_counts.items(), key=lambda item: item[1], reverse=True
            )[:8]
        ],
        "top_hosts": [
            {"host": row["host"], "count": int(row["n"]), "malicious": int(row["bad"] or 0)}
            for row in host_rows
        ],
    }
