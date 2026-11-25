"""FastAPI web app for QR Shield.

Run:
    python -m qrshield serve
    # or: uvicorn app.main:app --reload

Endpoints
---------
GET  /api/health              liveness, model state, uptime
GET  /api/info                version, model metadata, limits
POST /api/scan                scan one QR image (multipart)
POST /api/scan-batch          scan up to 20 QR images (multipart, repeated ``files``)
POST /api/scan-url            analyse a URL
GET  /api/history             paginated local scan history
GET  /api/history/{id}        one stored scan with full JSON
DELETE /api/history/{id}      delete one stored scan
DELETE /api/history           clear all history
GET  /api/stats               dashboard aggregates
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from qrshield import __version__, history
from qrshield.model import ModelNotFoundError, load_model
from qrshield.scanner import scan_image, scan_payload

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
MAX_UPLOAD_BYTES = 12 * 1024 * 1024
MAX_BATCH_FILES = 20
STARTED_AT = time.monotonic()


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        app.state.model = load_model()
        app.state.model_error = None
    except ModelNotFoundError as exc:
        app.state.model = None
        app.state.model_error = str(exc)
    try:
        await run_in_threadpool(history.init_db)
    except Exception as exc:  # history must never prevent the app starting
        app.state.history_error = str(exc)
    else:
        app.state.history_error = None
    yield


app = FastAPI(
    title="QR Shield",
    description=(
        "Local-first detection of phishing QR codes (quishing). Decodes the "
        "payload, scores the destination with a calibrated ML model and "
        "explainable rules, and records opt-in local history."
    ),
    version=__version__,
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class BatchUrlRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=20)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "version": __version__,
        "model_loaded": app.state.model is not None,
        "uptime_seconds": round(time.monotonic() - STARTED_AT, 1),
    }


@app.get("/health", include_in_schema=False)
async def health_alias():
    """Compatibility alias for container/orchestrator health checks."""
    return await health()


@app.get("/api/info")
async def info():
    model = app.state.model
    return {
        "app_version": __version__,
        "model_loaded": model is not None,
        "model_error": app.state.model_error,
        "history_error": getattr(app.state, "history_error", None),
        "limits": {
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
            "max_batch_files": MAX_BATCH_FILES,
            "max_url_length": 4096,
        },
        "model": model.info() if model is not None else None,
    }


def _check_image(file: UploadFile, data: bytes) -> Optional[str]:
    if file.content_type and not (
        file.content_type.startswith("image/")
        or file.content_type == "application/octet-stream"
    ):
        return "Please upload an image file (PNG, JPEG, WebP...)."
    if not data:
        return "The uploaded file is empty."
    if len(data) > MAX_UPLOAD_BYTES:
        return f"Image is too large (maximum {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)."
    return None


async def _record_image_result(
    result: Dict[str, Any], filename: Optional[str], source: str = "image"
) -> None:
    try:
        items = result.get("results") or []
        if items:
            for item in items:
                await run_in_threadpool(history.record_scan, item, source, filename)
        else:
            await run_in_threadpool(
                history.record_scan,
                {
                    "payload": f"(no QR decoded) {filename or ''}".strip(),
                    "verdict": "unknown",
                    "score": 0.0,
                    "reasons": [],
                },
                source,
                filename,
            )
    except Exception:
        # History is a convenience; never fail a scan because of it.
        pass


@app.post("/api/scan")
async def scan(
    file: UploadFile = File(...),
    save: bool = Query(True, description="Record this scan in local history."),
):
    data = await file.read()
    error = _check_image(file, data)
    if error:
        status = 413 if "too large" in error else 400 if "empty" in error else 415
        raise HTTPException(status_code=status, detail=error)
    result = await run_in_threadpool(scan_image, data, app.state.model)
    result["filename"] = file.filename
    if save:
        await _record_image_result(result, file.filename)
    if not result.get("ok") and str(result.get("error", "")).startswith("Could not open"):
        raise HTTPException(status_code=400, detail=result["error"])
    return JSONResponse(result)


@app.post("/api/scan-batch")
async def scan_batch(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No files were uploaded.")
    if len(files) > MAX_BATCH_FILES:
        raise HTTPException(
            status_code=413,
            detail=f"Too many files (maximum {MAX_BATCH_FILES} per batch).",
        )

    items: List[Dict[str, Any]] = []
    for file in files:
        data = await file.read()
        error = _check_image(file, data)
        if error:
            items.append(
                {
                    "ok": False,
                    "filename": file.filename,
                    "error": error,
                    "decoded_count": 0,
                    "results": [],
                    "overall": None,
                }
            )
            continue
        result = await run_in_threadpool(scan_image, data, app.state.model)
        result["filename"] = file.filename
        await _record_image_result(result, file.filename)
        items.append(result)

    decoded = [item for item in items if item.get("ok")]
    warnings: List[str] = []
    failed = [item for item in items if not item.get("ok")]
    if failed:
        warnings.append(f"{len(failed)} file(s) could not be decoded.")
    if len(decoded) > 1:
        verdicts = {item["overall"]["verdict"] for item in decoded}
        if "malicious" in verdicts and ("safe" in verdicts or "allowlisted" in verdicts):
            warnings.append("This batch mixes safe and malicious targets; inspect each result.")
    worst = max(
        (item for item in decoded if item.get("overall")),
        key=lambda item: item["overall"]["score"],
        default=None,
    )
    overall = (
        {**worst["overall"], "warnings": worst["overall"].get("warnings", []) + warnings}
        if worst
        else {"score": 0.0, "verdict": "unknown", "warnings": warnings}
    )
    return {
        "ok": True,
        "count": len(items),
        "decoded_count": len(decoded),
        "results": items,
        "overall": overall,
    }


@app.post("/api/scan-url")
async def api_scan_url(
    body: UrlRequest,
    save: bool = Query(True, description="Record this scan in local history."),
):
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is empty.")
    if len(url) > 4096:
        raise HTTPException(status_code=400, detail="URL is too long.")
    result = await run_in_threadpool(scan_payload, url, app.state.model)
    if save:
        try:
            await run_in_threadpool(history.record_scan, result, "url")
        except Exception:
            pass
    return JSONResponse(result)


@app.post("/api/scan-url/batch")
async def api_scan_url_batch(body: BatchUrlRequest):
    results = []
    for url in body.urls:
        url = url.strip()
        if not url or len(url) > 4096:
            continue
        result = await run_in_threadpool(scan_payload, url, app.state.model)
        try:
            await run_in_threadpool(history.record_scan, result, "url")
        except Exception:
            pass
        results.append(result)
    if not results:
        raise HTTPException(status_code=400, detail="No valid URLs were provided.")
    worst = max(results, key=lambda item: item["score"])
    return {
        "count": len(results),
        "results": results,
        "overall": {
            "score": worst["score"],
            "verdict": worst["verdict"],
            "warnings": [],
        },
    }


@app.get("/api/history")
async def api_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = Query(None),
    q: Optional[str] = Query(None, max_length=200),
):
    return await run_in_threadpool(
        history.list_scans,
        limit,
        offset,
        verdict,
        q,
    )


@app.get("/api/history/{scan_id}")
async def api_history_item(scan_id: int):
    item = await run_in_threadpool(history.get_scan, scan_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return item


@app.delete("/api/history/{scan_id}")
async def api_history_delete(scan_id: int):
    deleted = await run_in_threadpool(history.delete_scan, scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"deleted": True, "id": scan_id}


@app.delete("/api/history")
async def api_history_clear():
    removed = await run_in_threadpool(history.clear_history)
    return {"deleted": removed}


@app.get("/api/stats")
async def api_stats():
    return await run_in_threadpool(history.stats)
