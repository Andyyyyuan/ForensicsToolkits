from pathlib import Path

from app.services.cyberchef_service import cyberchef_service
from app.tools.base import BaseTool
from app.tools.registry import tool_registry


class EncodingConverterTool(BaseTool):
    tool_id = "encoding_converter"
    name = "编码转换"
    description = "接入 CyberChef 进行编码识别、编码转换与常见取证数据解码。"
    input_types = []
    requires_file = False

    async def run(self, file_path: str | Path, params: dict | None = None) -> dict:
        return {
            "cyberchef_available": cyberchef_service.is_available(),
            "cyberchef_url": cyberchef_service.get_public_url(),
            "cyberchef_dir": str(cyberchef_service.get_directory()),
        }


def register_encoding_converter_tool() -> None:
    if not tool_registry.has_tool("encoding_converter"):
        tool_registry.register(EncodingConverterTool())
