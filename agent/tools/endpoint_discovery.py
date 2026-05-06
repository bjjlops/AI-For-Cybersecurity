"""Substantive recon tool for Juice Shop endpoint discovery."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from .base import tool
from .http_tool import _get_client


class EndpointDiscoveryParams(BaseModel):
    start_paths: list[str] = Field(
        default_factory=lambda: ["/"],
        description="Local paths to crawl from. Paths must stay inside the configured target.",
    )
    max_pages: int = Field(
        default=8,
        ge=1,
        le=30,
        description="Maximum HTML/JS resources to fetch while discovering endpoints.",
    )


def _local_path(candidate: str) -> str | None:
    if not candidate:
        return None
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return None
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


@tool(
    name="endpoint_discovery",
    description=(
        "Crawl local Juice Shop HTML and JavaScript resources, extract links, "
        "script references, API paths, and common routes, and probe status codes. "
        "Use this during reconnaissance before targeted attacks."
    ),
    params=EndpointDiscoveryParams,
)
def endpoint_discovery(
    start_paths: list[str] | None = None,
    max_pages: int = 8,
) -> dict[str, Any]:
    client = _get_client()
    queue: list[str] = []
    seen: set[str] = set()
    api_paths: set[str] = set()
    links: set[str] = set()
    scripts: set[str] = set()
    statuses: dict[str, int | str] = {}

    for path in start_paths or ["/"]:
        local = _local_path(path)
        if local:
            queue.append(local)

    common_paths = [
        "/#/score-board",
        "/rest/products/search?q=",
        "/rest/user/login",
        "/api/Challenges/",
        "/api/Feedbacks/",
        "/api/Users/",
        "/ftp",
        "/robots.txt",
        "/.well-known/security.txt",
    ]

    api_pattern = re.compile(
        r"""["'`](\/(?:api|rest|ftp|assets|socket.io)\/[A-Za-z0-9_./{}?&=%:+\-]*)["'`]"""
    )
    route_pattern = re.compile(r"""["'`](\/#\/[A-Za-z0-9_./?&=%:+\-]*)["'`]""")

    while queue and len(seen) < max_pages:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        try:
            response = client.get(path)
            statuses[path] = response.status_code
        except Exception as exc:
            statuses[path] = f"error: {exc}"
            continue

        content_type = response.headers.get("content-type", "")
        text = response.text
        for match in api_pattern.findall(text):
            api_paths.add(match)
        for match in route_pattern.findall(text):
            links.add(match)

        if "html" in content_type or path == "/":
            soup = BeautifulSoup(text, "html.parser")
            for anchor in soup.find_all("a", href=True):
                local = _local_path(anchor["href"])
                if local:
                    links.add(local)
            for script in soup.find_all("script", src=True):
                local = _local_path(script["src"])
                if local:
                    scripts.add(local)
                    queue.append(local)
        elif "javascript" in content_type or path.endswith(".js"):
            for match in api_pattern.findall(text):
                api_paths.add(match)

    for path in common_paths:
        local = _local_path(path)
        if not local:
            continue
        try:
            response = client.get(local)
            statuses[local] = response.status_code
        except Exception as exc:
            statuses[local] = f"error: {exc}"

    interesting = sorted(api_paths | set(common_paths))
    return {
        "visited": sorted(seen),
        "links": sorted(links),
        "scripts": sorted(scripts),
        "api_paths": interesting,
        "status_codes": statuses,
        "summary": f"Discovered {len(interesting)} API/common paths and probed {len(statuses)} resources.",
    }
