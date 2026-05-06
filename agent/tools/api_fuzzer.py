"""Bounded API fuzzer for known Juice Shop surfaces."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .base import tool
from .http_tool import _get_client


class ApiFuzzerParams(BaseModel):
    include_write_probes: bool = Field(
        default=True,
        description="Run harmless write probes such as feedback submission.",
    )
    include_file_probes: bool = Field(
        default=True,
        description="Probe known local file/FTP routes for information disclosure.",
    )


@tool(
    name="api_fuzzer",
    description=(
        "Probe bounded Juice Shop API patterns for low-risk findings: security "
        "headers, public metadata, feedback validation, and local file exposure."
    ),
    params=ApiFuzzerParams,
)
def api_fuzzer(
    include_write_probes: bool = True,
    include_file_probes: bool = True,
) -> dict[str, Any]:
    client = _get_client()
    evidence: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    get_paths = [
        "/",
        "/metrics",
        "/api/Challenges/",
        "/rest/admin/application-configuration",
        "/rest/products/search?q=",
        "/rest/user/whoami",
    ]
    if include_file_probes:
        get_paths.extend(
            [
                "/ftp",
                "/ftp/legal.md",
                "/ftp/acquisitions.md",
                "/ftp/package.json.bak%2500.md",
                "/ftp/coupons_2013.md.bak%2500.md",
                "/ftp/eastere.gg%2500.md",
                "/support/logs/access.log",
                "/robots.txt",
                "/security.txt",
                "/.well-known/security.txt",
            ]
        )

    for path in get_paths:
        try:
            response = client.get(path)
            item = {
                "endpoint": f"GET {path}",
                "status": response.status_code,
                "content_type": response.headers.get("content-type"),
                "body_excerpt": response.text[:600],
            }
            evidence.append(item)
            if path == "/" and "x-frame-options" not in {k.lower() for k in response.headers}:
                findings.append(
                    {
                        "title": "Missing clickjacking protection header",
                        "severity": "Medium",
                        "endpoint": "GET /",
                        "evidence": item,
                        "reproduction": "Fetch / and observe that X-Frame-Options is absent.",
                        "remediation": (
                            "Set Content-Security-Policy frame-ancestors and/or X-Frame-Options "
                            "for browser-rendered pages."
                        ),
                    }
                )
            if path.startswith("/ftp") and response.status_code == 200:
                findings.append(
                    {
                        "title": "Public file area is browsable",
                        "severity": "Low",
                        "endpoint": f"GET {path}",
                        "evidence": item,
                        "reproduction": f"Request {path} without authentication and observe a successful response.",
                        "remediation": (
                            "Disable directory-style exposure for sensitive static paths and require "
                            "authorization checks before serving non-public files."
                        ),
                    }
                )
            if path == "/metrics" and response.status_code == 200:
                findings.append(
                    {
                        "title": "Prometheus metrics endpoint is exposed",
                        "severity": "Low",
                        "endpoint": "GET /metrics",
                        "evidence": item,
                        "reproduction": "Request /metrics without authentication and observe application metrics.",
                        "remediation": (
                            "Restrict metrics endpoints to internal networks or authenticated "
                            "monitoring clients, and avoid exposing operational counters publicly."
                        ),
                    }
                )
            if "%2500" in path and response.status_code == 200:
                findings.append(
                    {
                        "title": "Encoded null byte bypass exposes restricted backup files",
                        "severity": "High",
                        "endpoint": f"GET {path}",
                        "evidence": item,
                        "reproduction": (
                            "Request the encoded null-byte path and observe that a backup/easter egg "
                            "file is served despite extension filtering."
                        ),
                        "remediation": (
                            "Canonicalize and decode paths before validation, reject null bytes, "
                            "and avoid serving backup files from public static directories."
                        ),
                    }
                )
        except Exception as exc:
            evidence.append({"endpoint": f"GET {path}", "error": f"{type(exc).__name__}: {exc}"})

    if include_write_probes:
        captcha_id = 0
        captcha_answer = "0"
        try:
            captcha = client.get("/rest/captcha/").json()
            captcha_id = int(captcha.get("captchaId", 0))
            captcha_answer = str(captcha.get("answer", "0"))
        except Exception:
            pass

        feedback = {
            "UserId": 1,
            "captchaId": captcha_id,
            "captcha": captcha_answer,
            "comment": "Automated authorized local security test feedback.",
            "rating": 0,
        }
        try:
            response = client.post("/api/Feedbacks/", json=feedback)
            item = {
                "endpoint": "POST /api/Feedbacks/",
                "status": response.status_code,
                "payload": feedback,
                "body_excerpt": response.text[:600],
            }
            evidence.append(item)
            if response.status_code in {200, 201}:
                findings.append(
                    {
                        "title": "Feedback endpoint accepts forged zero-star submission",
                        "severity": "Medium",
                        "endpoint": "POST /api/Feedbacks/",
                        "evidence": item,
                        "reproduction": (
                            "Fetch /rest/captcha/, submit the answer with UserId=1 and rating=0 "
                            "to /api/Feedbacks/, and observe that the server stores the feedback."
                        ),
                        "remediation": (
                            "Bind feedback ownership to the authenticated session, validate rating "
                            "range server-side, and avoid trusting client-supplied UserId values."
                        ),
                    }
                )
        except Exception as exc:
            evidence.append(
                {"endpoint": "POST /api/Feedbacks/", "error": f"{type(exc).__name__}: {exc}"}
            )

    return {
        "findings": findings,
        "evidence": evidence,
        "summary": f"API fuzzer captured {len(evidence)} observations and {len(findings)} findings.",
    }
