"""Tool registry. Import this module to auto-register all tools."""

from .base import Tool, ToolRegistry, REGISTRY, tool
from . import (  # noqa: F401
    api_fuzzer,
    browser_explorer,
    challenge_solver,
    challenge_status,
    endpoint_discovery,
    http_tool,
    jwt_inspector,
    recon_tool,
    sql_injection,
)

__all__ = ["Tool", "ToolRegistry", "tool", "REGISTRY"]
