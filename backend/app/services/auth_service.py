from __future__ import annotations

import hashlib
from dataclasses import dataclass

from fastapi import Header, HTTPException

from app.core.config import settings


@dataclass
class AuthContext:
    role: str
    token_fingerprint: str


def _parse_tokens() -> dict[str, str]:
    raw = (settings.api_tokens or "").strip()
    out: dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(","):
        p = part.strip()
        if not p or ":" not in p:
            continue
        role, tok = p.split(":", 1)
        role = role.strip().lower()
        tok = tok.strip()
        if role and tok:
            out[tok] = role
    return out


def _fp(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def require_role(*allowed: str):
    allowed_set = {x.lower() for x in allowed}

    def _dep(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> AuthContext:
        token_map = _parse_tokens()
        if not token_map:
            raise HTTPException(status_code=503, detail="api_tokens_not_configured")
        if not x_api_key or x_api_key not in token_map:
            raise HTTPException(status_code=401, detail="invalid_api_key")
        role = token_map[x_api_key]
        if role not in allowed_set:
            raise HTTPException(status_code=403, detail=f"role_not_allowed:{role}")
        return AuthContext(role=role, token_fingerprint=_fp(x_api_key))

    return _dep
