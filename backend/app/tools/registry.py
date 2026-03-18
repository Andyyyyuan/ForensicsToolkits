from pathlib import Path
from typing import Any

from app.tools.base import BaseTool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        if tool.tool_id in self._tools:
            raise ValueError(f"Tool already registered: {tool.tool_id}")
        self._tools[tool.tool_id] = tool

    def has_tool(self, tool_id: str) -> bool:
        return tool_id in self._tools

    def get_tool(self, tool_id: str) -> BaseTool:
        try:
            return self._tools[tool_id]
        except KeyError as exc:
            raise KeyError(f"Tool not found: {tool_id}") from exc

    def list_tools(self) -> list[BaseTool]:
        return list(self._tools.values())

    async def run_tool(
        self,
        tool_id: str,
        file_path: str | Path,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tool = self.get_tool(tool_id)
        return await tool.run(file_path=file_path, params=params or {})


tool_registry = ToolRegistry()
