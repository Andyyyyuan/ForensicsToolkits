from pathlib import Path
from typing import Any

from app.tools.implementations import (
    register_encoding_converter_tool,
    register_hash_tool,
    register_hashcat_gui_tool,
    register_log_parser_tool,
    register_sqlite2csv_tool,
    register_timestamp_parser_tool,
)
from app.tools.registry import tool_registry

register_encoding_converter_tool()
register_log_parser_tool()
register_hash_tool()
register_hashcat_gui_tool()
register_sqlite2csv_tool()
register_timestamp_parser_tool()


class ToolService:
    def get_tool(self, tool_id: str):
        return tool_registry.get_tool(tool_id)

    def list_tools(self):
        return tool_registry.list_tools()

    async def run_tool(
        self,
        tool_id: str,
        file_path: str | Path,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await tool_registry.run_tool(tool_id=tool_id, file_path=file_path, params=params or {})


tool_service = ToolService()


async def run_tool(
    tool_id: str,
    file_path: str | Path,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return await tool_service.run_tool(tool_id=tool_id, file_path=file_path, params=params or {})
