"""JWT inspection tool for tokens captured during local testing."""

from __future__ import annotations

import base64
import json
from typing import Any

from pydantic import BaseModel, Field

from .base import tool


class JwtInspectorParams(BaseModel):
    token: str = Field(..., description="JWT string to decode without verifying the signature.")


def _decode_part(part: str) -> dict[str, Any] | str:
    padded = part + "=" * (-len(part) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return raw.decode("utf-8", errors="replace")


@tool(
    name="jwt_inspector",
    description=(
        "Decode a JWT header and payload without verifying it. Reports algorithm, "
        "claims, and obvious weak-token indicators for evidence collection."
    ),
    params=JwtInspectorParams,
)
def jwt_inspector(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Token does not have three JWT sections."}
    try:
        header = _decode_part(parts[0])
        payload = _decode_part(parts[1])
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}

    alg = header.get("alg") if isinstance(header, dict) else None
    weak = alg is None or str(alg).lower() in {"none", "null"}
    return {
        "header": header,
        "payload": payload,
        "algorithm": alg,
        "weak_algorithm": weak,
        "summary": f"JWT decoded with alg={alg!r}; weak_algorithm={weak}.",
    }
