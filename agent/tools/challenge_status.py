"""Tool for reading Juice Shop challenge status."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .base import tool
from .http_tool import _get_client


class ChallengeStatusParams(BaseModel):
    only_solved: bool = Field(
        default=False,
        description="When true, return only solved challenges in the detail list.",
    )


@tool(
    name="challenge_status",
    description=(
        "Query /api/Challenges/ and summarize solved/unsolved challenge status. "
        "Use before and after exploitation to measure progress."
    ),
    params=ChallengeStatusParams,
)
def challenge_status(only_solved: bool = False) -> dict[str, Any]:
    client = _get_client()
    try:
        response = client.get("/api/Challenges/")
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}

    raw = payload.get("data", payload)
    challenges: list[dict[str, Any]] = []
    solved = 0
    by_category: dict[str, dict[str, int]] = {}
    for item in raw:
        is_solved = bool(item.get("solved"))
        solved += int(is_solved)
        category = item.get("category") or "Uncategorized"
        bucket = by_category.setdefault(category, {"solved": 0, "total": 0})
        bucket["solved"] += int(is_solved)
        bucket["total"] += 1
        if only_solved and not is_solved:
            continue
        challenges.append(
            {
                "key": item.get("key") or item.get("name"),
                "name": item.get("name"),
                "category": category,
                "difficulty": item.get("difficulty"),
                "solved": is_solved,
                "description": item.get("description", ""),
            }
        )

    total = len(raw)
    return {
        "solved": solved,
        "total": total,
        "fraction": round(solved / total, 3) if total else 0,
        "by_category": by_category,
        "challenges": challenges[:80],
        "summary": f"{solved}/{total} challenges solved.",
    }
