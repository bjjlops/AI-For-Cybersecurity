"""Autonomous Juice Shop pentesting agent.

The implementation uses a small Plan-and-Execute/ReAct hybrid. A bounded plan
selects safe Juice Shop probes, each tool result becomes an observation, and the
agent updates structured memory after every step. The LLM is used for optional
run summarization, while exploitation is delegated to deterministic tools so a
single bad model turn does not derail the run.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .llm import LLMClient, Message
from .tools import REGISTRY


@dataclass
class Finding:
    title: str
    severity: str
    endpoint: str
    evidence: dict[str, Any]
    reproduction: str
    remediation: str
    source_tool: str


@dataclass
class ToolObservation:
    step: int
    tool: str
    arguments: dict[str, Any]
    ok: bool
    summary: str
    result: dict[str, Any]


@dataclass
class AgentMemory:
    target_url: str
    started_at: str
    plan: list[str] = field(default_factory=list)
    observations: list[ToolObservation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    solved_before: int | None = None
    solved_after: int | None = None
    auth_token: str | None = None
    solved_challenges: list[str] = field(default_factory=list)
    progress_events: list[dict[str, Any]] = field(default_factory=list)
    final_message: str = ""

    def compact(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "steps": len(self.observations),
            "findings": [asdict(f) for f in self.findings],
            "discovered_paths": self.discovered_paths[:40],
            "solved_before": self.solved_before,
            "solved_after": self.solved_after,
            "solved_challenges": self.solved_challenges,
            "progress_events": self.progress_events[-20:],
            "observation_summaries": [
                {
                    "step": obs.step,
                    "tool": obs.tool,
                    "ok": obs.ok,
                    "summary": obs.summary,
                }
                for obs in self.observations[-20:]
            ],
        }


class PentestAgent:
    def __init__(
        self,
        llm: LLMClient,
        target_url: str,
        max_steps: int = 100,
        log_dir: Path | None = None,
    ) -> None:
        self.llm = llm
        self.target_url = target_url.rstrip("/")
        self.max_steps = max_steps
        self.log_dir = log_dir or Path("agent_logs")
        self.registry = REGISTRY
        self.tool_calls = 0
        self.target_score = int(os.environ.get("TARGET_SOLVED_SCORE", "50"))
        self.system_prompt = self._load_prompt("system.md")
        self.report_prompt = self._load_prompt("report.md")
        self.run_dir = self._new_run_dir(self.log_dir)
        self.memory = AgentMemory(
            target_url=self.target_url,
            started_at=datetime.now(timezone.utc).isoformat(),
            plan=self._build_initial_plan(),
        )
        self._enforce_local_target()
        os.environ["TARGET_URL"] = self.target_url

    def run(self) -> dict[str, Any]:
        """Run the bounded autonomous plan and return a CLI-friendly summary."""
        self._log_event("run_start", {"target": self.target_url, "plan": self.memory.plan})

        action_queue: list[tuple[str, dict[str, Any]]] = [
            ("challenge_status", {"only_solved": False}),
            ("endpoint_discovery", {"start_paths": ["/"], "max_pages": 12}),
            ("api_fuzzer", {"include_write_probes": True, "include_file_probes": True}),
            (
                "sql_injection_tester",
                {"include_login_tests": True, "include_search_tests": True},
            ),
            (
                "challenge_solver_suite",
                {"include_xxe": True, "include_uploads": True, "target_score": self.target_score},
            ),
            (
                "browser_explorer",
                {
                    "include_xss": True,
                    "include_web3": True,
                    "screenshot_dir": str(self.run_dir / "browser_evidence"),
                },
            ),
            ("challenge_status", {"only_solved": False}),
        ]

        steps_taken = 0
        while action_queue and steps_taken < self.max_steps:
            steps_taken += 1
            tool_name, arguments = action_queue.pop(0)
            observation = self._invoke_tool(steps_taken, tool_name, arguments)
            self._record_observation(observation)
            self._print_progress(observation)

            if tool_name == "sql_injection_tester" and self.memory.auth_token:
                action_queue.insert(0, ("jwt_inspector", {"token": self.memory.auth_token}))
            if (
                tool_name == "challenge_status"
                and self.memory.solved_after is not None
                and self.memory.solved_after >= self.target_score
                and steps_taken >= 6
            ):
                self._log_event(
                    "target_score_reached",
                    {"target_score": self.target_score, "solved": self.memory.solved_after},
                )
                break

        self.memory.final_message = self._summarize_run(steps_taken)
        self._write_json("memory.json", self.memory.compact())
        self._log_event("run_complete", self.memory.compact())
        return {
            "steps_taken": steps_taken,
            "tool_calls": self.tool_calls,
            "findings": len(self.memory.findings),
            "solved_before": self.memory.solved_before,
            "solved_after": self.memory.solved_after,
            "target_score": self.target_score,
            "log_dir": str(self.run_dir),
            "final_message": self.memory.final_message,
        }

    def generate_report(self, output_path: Path) -> None:
        """Generate the final pentest report at output_path."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = [
            "# OWASP Juice Shop Pentest Report",
            "",
            f"**Target:** `{self.target_url}`",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Agent steps:** {len(self.memory.observations)}",
            f"**Tool calls:** {self.tool_calls}",
            "",
            "## Executive Summary",
            "",
            self.memory.final_message
            or "The agent completed its bounded local Juice Shop assessment and recorded structured evidence.",
            "",
            "## Scope and Safety",
            "",
            "Testing was limited to the configured local OWASP Juice Shop target. "
            "The agent avoided destructive actions, denial-of-service behavior, credential stuffing, "
            "and third-party targets.",
            "",
            "## Scoreboard Snapshot",
            "",
            f"- Solved before run: {self._unknown(self.memory.solved_before)}",
            f"- Solved after run: {self._unknown(self.memory.solved_after)}",
            f"- Target score: {self.target_score}",
            "",
            "## Challenge Progress",
            "",
        ]
        if self.memory.progress_events:
            for event in self.memory.progress_events:
                lines.append(
                    f"- `{event.get('tool')}`: {event.get('solved_before')} -> "
                    f"{event.get('solved_after')} solved; new: "
                    f"{', '.join(event.get('newly_solved', [])) or 'none'}"
                )
            lines.append("")
        else:
            lines.extend(["No per-phase challenge progress was recorded.", ""])

        lines.extend(
            [
            "## Findings",
            "",
            ]
        )

        if not self.memory.findings:
            lines.extend(
                [
                    "No confirmed findings were recorded. Review the run log for failed probes and "
                    "environment issues.",
                    "",
                ]
            )
        else:
            grouped: dict[str, list[Finding]] = {}
            for finding in self.memory.findings:
                grouped.setdefault(finding.title, []).append(finding)

            for title, findings in grouped.items():
                representative = findings[0]
                lines.extend(
                    [
                        f"### {title}",
                        "",
                        f"- **Severity:** {representative.severity}",
                        f"- **Affected endpoint:** `{representative.endpoint}`",
                        f"- **Detected by:** `{representative.source_tool}`",
                        "",
                        "**Evidence:**",
                        "",
                        "```json",
                        self._redacted_json(representative.evidence)[:3500],
                        "```",
                        "",
                        f"**Reproduction:** {representative.reproduction}",
                        "",
                        f"**Remediation:** {representative.remediation}",
                        "",
                    ]
                )

        lines.extend(
            [
                "## Tool Observations",
                "",
            ]
        )
        for obs in self.memory.observations:
            lines.append(
                f"- Step {obs.step}: `{obs.tool}` with `{self._redacted_arguments(obs.arguments)}` -> {obs.summary}"
            )

        lines.extend(
            [
                "",
                "## Artifacts",
                "",
                f"- Run logs: `{self.run_dir}`",
                f"- Compact memory: `{self.run_dir / 'memory.json'}`",
                "",
            ]
        )
        output_path.write_text("\n".join(lines), encoding="utf-8")

    def _build_initial_plan(self) -> list[str]:
        return [
            "Verify scoreboard status with challenge_status.",
            "Discover local HTML, JavaScript, route, and API surfaces.",
            "Run bounded API probes for metadata, files, headers, and feedback behavior.",
            "Run SQL injection probes against login and search endpoints.",
            "Run deterministic challenge-aware solver workflows with progress checks.",
            "Run browser exploration for Angular routes and DOM-only payloads.",
            "Inspect any captured JWT and re-check scoreboard status.",
            "Generate a structured report from stored findings and evidence.",
        ]

    def _enforce_local_target(self) -> None:
        parsed = urlparse(self.target_url)
        allowed_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in allowed_hosts:
            raise ValueError(
                "This agent is scoped only to local Juice Shop targets such as "
                "http://localhost:3000."
            )

    def _new_run_dir(self, base: Path) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_dir = base / stamp
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def _load_prompt(self, name: str) -> str:
        prompt_path = Path(__file__).parent / "prompts" / name
        try:
            return prompt_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def _invoke_tool(
        self,
        step: int,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolObservation:
        tool = self.registry.get(tool_name)
        if tool is None:
            result = {"error": f"Tool {tool_name!r} is not registered."}
            return ToolObservation(step, tool_name, arguments, False, result["error"], result)

        self.tool_calls += 1
        try:
            raw = tool.invoke(arguments)
            result = raw if isinstance(raw, dict) else {"result": raw}
            ok = "error" not in result
            summary = str(result.get("summary") or result.get("error") or "tool completed")
            return ToolObservation(step, tool_name, arguments, ok, summary, result)
        except Exception as exc:
            result = {"error": f"{type(exc).__name__}: {exc}"}
            return ToolObservation(step, tool_name, arguments, False, result["error"], result)

    def _record_observation(self, observation: ToolObservation) -> None:
        self.memory.observations.append(observation)
        result = observation.result

        if observation.tool == "endpoint_discovery":
            paths = result.get("api_paths", [])
            if isinstance(paths, list):
                combined = set(self.memory.discovered_paths)
                combined.update(str(path) for path in paths)
                self.memory.discovered_paths = sorted(combined)

        if observation.tool == "challenge_status" and isinstance(result.get("solved"), int):
            solved = int(result["solved"])
            if self.memory.solved_before is None:
                self.memory.solved_before = solved
            self.memory.solved_after = solved
            challenges = result.get("challenges", [])
            if isinstance(challenges, list):
                self.memory.solved_challenges = sorted(
                    str(item.get("name"))
                    for item in challenges
                    if isinstance(item, dict) and item.get("solved") and item.get("name")
                )

        if isinstance(result.get("solved_before"), int) and isinstance(result.get("solved_after"), int):
            before = int(result["solved_before"])
            after = int(result["solved_after"])
            self.memory.solved_after = after
            if self.memory.solved_before is None:
                self.memory.solved_before = before
            event = {
                "tool": observation.tool,
                "solved_before": before,
                "solved_after": after,
                "newly_solved": result.get("newly_solved", []),
            }
            self.memory.progress_events.append(event)

        if observation.tool == "sql_injection_tester" and result.get("auth_token"):
            self.memory.auth_token = str(result["auth_token"])

        for item in result.get("findings", []) if isinstance(result.get("findings"), list) else []:
            if not isinstance(item, dict):
                continue
            finding = Finding(
                title=str(item.get("title", "Untitled finding")),
                severity=str(item.get("severity", "Informational")),
                endpoint=str(item.get("endpoint", "unknown")),
                evidence=item.get("evidence", {}),
                reproduction=str(item.get("reproduction", "See evidence.")),
                remediation=str(item.get("remediation", "Review and harden the affected behavior.")),
                source_tool=observation.tool,
            )
            if not self._already_recorded(finding):
                self.memory.findings.append(finding)

        self._log_event("tool_observation", asdict(observation))

    def _already_recorded(self, candidate: Finding) -> bool:
        for existing in self.memory.findings:
            if (
                existing.title == candidate.title
                and existing.endpoint == candidate.endpoint
                and existing.source_tool == candidate.source_tool
            ):
                return True
        return False

    def _summarize_run(self, steps_taken: int) -> str:
        fallback = (
            f"Completed {steps_taken} steps against the local Juice Shop target, "
            f"recording {len(self.memory.findings)} findings. "
            f"Scoreboard solved count moved from {self._unknown(self.memory.solved_before)} "
            f"to {self._unknown(self.memory.solved_after)}."
        )
        try:
            messages = [
                Message(
                    role="system",
                    content=(
                        self.system_prompt
                        or "You summarize authorized local OWASP Juice Shop pentest runs. "
                        "Be concise and do not invent findings."
                    ),
                ),
                Message(
                    role="user",
                    content=(
                        (self.report_prompt + "\n\n" if self.report_prompt else "")
                        +
                        "Summarize this run in 2-3 sentences for a pentest report:\n"
                        + json.dumps(self.memory.compact(), indent=2, default=str)[:12000]
                    ),
                ),
            ]
            response = self.llm.complete(messages=messages)
            summary = (response.content or "").strip()
            if not summary or len(summary) > 900 or "\n##" in summary or "\n###" in summary:
                return fallback
            return summary
        except Exception as exc:
            self._log_event("llm_summary_failed", {"error": f"{type(exc).__name__}: {exc}"})
            return fallback

    def _log_event(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "payload": payload,
        }
        log_path = self.run_dir / "events.jsonl"
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")

    def _write_json(self, name: str, payload: dict[str, Any]) -> None:
        (self.run_dir / name).write_text(
            json.dumps(payload, indent=2, default=str),
            encoding="utf-8",
        )

    def _unknown(self, value: int | None) -> str:
        return "unknown" if value is None else str(value)

    def _redacted_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = {}
        for key, value in arguments.items():
            if "token" in key.lower() and isinstance(value, str):
                redacted[key] = value[:24] + "...[redacted]"
            else:
                redacted[key] = value
        return redacted

    def _redacted_json(self, payload: Any) -> str:
        text = json.dumps(payload, indent=2, default=str)
        text = re.sub(
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "[redacted-jwt]",
            text,
        )
        text = re.sub(
            r"(?i)(sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,})",
            "[redacted-api-key]",
            text,
        )
        return text

    def _print_progress(self, observation: ToolObservation) -> None:
        result = observation.result
        if isinstance(result.get("solved_before"), int) and isinstance(result.get("solved_after"), int):
            newly = result.get("newly_solved", [])
            print(
                f"[phase] {observation.tool}: "
                f"{result['solved_before']} -> {result['solved_after']} solved; "
                f"new: {', '.join(newly) if newly else 'none'}"
            )
        else:
            print(f"[phase] {observation.tool}: {observation.summary}")
