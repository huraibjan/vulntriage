"""Request protection for write and cost-bearing endpoints."""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict, Optional

from fastapi import Header, HTTPException, Request

from app.core.settings import get_settings


def require_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    """Enforce X-API-Key when VULNTRIAGE_API_KEY is configured."""
    expected = get_settings().vulntriage_api_key
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="A valid X-API-Key header is required.")


_hits: Dict[str, Deque[float]] = defaultdict(deque)
_hits_lock = Lock()


def llm_rate_limit(request: Request) -> None:
    """Sliding one-minute window per client for LLM-backed requests."""
    limit = get_settings().llm_rate_limit_per_minute
    if limit <= 0:
        return
    forwarded = request.headers.get("x-forwarded-for", "")
    client = forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")
    now = time.monotonic()
    with _hits_lock:
        window = _hits[client]
        while window and now - window[0] > 60.0:
            window.popleft()
        if len(window) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"LLM brief limit of {limit} per minute reached. Retry shortly.",
            )
        window.append(now)
