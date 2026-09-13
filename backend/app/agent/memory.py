"""
Investigation memory for CyberNeura Agent.
Provides tool-call caching and short-term memory during an investigation session.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional
from app.agent.tool_result import ToolResult


class InvestigationMemory:
    """
    Session-scoped memory holding cached tool calls, collected evidence,
    and unresolved questions.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._tool_cache: Dict[str, ToolResult] = {}
        self._unresolved_questions: List[str] = []
        self._executed_tools: List[str] = []

    @staticmethod
    def _make_key(tool_name: str, arguments: Dict[str, Any]) -> str:
        # Canonical JSON representation for hashing
        serialized = json.dumps(arguments, sort_keys=True)
        h = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return f"{tool_name}:{h}"

    def get_cached_tool_result(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[ToolResult]:
        key = self._make_key(tool_name, arguments)
        return self._tool_cache.get(key)

    def cache_tool_result(self, tool_name: str, arguments: Dict[str, Any], result: ToolResult) -> None:
        key = self._make_key(tool_name, arguments)
        self._tool_cache[key] = result
        if tool_name not in self._executed_tools:
            self._executed_tools.append(tool_name)

    def is_tool_executed(self, tool_name: str) -> bool:
        return tool_name in self._executed_tools

    def add_unresolved_question(self, question: str) -> None:
        if question not in self._unresolved_questions:
            self._unresolved_questions.append(question)

    def clear_unresolved_questions(self) -> None:
        self._unresolved_questions.clear()

    @property
    def unresolved_questions(self) -> List[str]:
        return list(self._unresolved_questions)

    @property
    def executed_tools(self) -> List[str]:
        return list(self._executed_tools)
