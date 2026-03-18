from pathlib import Path
from typing import Any

from app.services.hashcat_service import hashcat_service
from app.tools.base import BaseTool
from app.tools.registry import tool_registry


class HashcatGUITool(BaseTool):
    tool_id = "hashcat_gui"
    name = "Hashcat GUI"
    description = "以图形化方式启动 Hashcat 字典或掩码任务。"
    input_types = [".txt", ".hash"]

    async def run(self, file_path: str | Path, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return hashcat_service.start_task(hash_file_path=str(file_path), params=params or {})


def register_hashcat_gui_tool() -> None:
    if not tool_registry.has_tool("hashcat_gui"):
        tool_registry.register(HashcatGUITool())
