"""Limitation de debit (rate limiting) en memoire, sans dependance externe.

Audit cyber M2 : les endpoints d'inference (`/api/analyze`, `/api/analyze/batch`,
`/api/upload`) declenchent du calcul ML et doivent etre proteges contre les abus.
On applique une fenetre glissante simple par adresse IP cliente. Suffisant pour
un deploiement mono-processus ; pour un cluster, preferer Redis/slowapi.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Request
from fastapi.responses import JSONResponse

from src.common.logging_conf import get_logger

logger = get_logger(__name__)

# Nombre de requetes autorisees par fenetre et duree de la fenetre (secondes).
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
WINDOW_SECONDS = 60.0

# Prefixes proteges (endpoints couteux).
_PROTECTED_PREFIXES = ("/api/analyze", "/api/upload")

_hits: Dict[str, Deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def rate_limit_middleware(request: Request, call_next):
    """Middleware FastAPI : 429 si l'IP depasse le quota sur un endpoint protege."""
    path = request.url.path
    if request.method == "POST" and path.startswith(_PROTECTED_PREFIXES):
        ip = _client_ip(request)
        now = time.monotonic()
        with _lock:
            dq = _hits[ip]
            while dq and now - dq[0] > WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= RATE_LIMIT:
                retry = int(WINDOW_SECONDS - (now - dq[0])) + 1
                logger.warning("Rate limit depasse pour %s sur %s", ip, path)
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Trop de requetes, reessayez plus tard."},
                    headers={"Retry-After": str(retry)},
                )
            dq.append(now)
    return await call_next(request)


__all__ = ["rate_limit_middleware", "RATE_LIMIT", "WINDOW_SECONDS"]
