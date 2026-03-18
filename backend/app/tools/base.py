from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseTool(ABC):
    tool_id: str
    name: str
    description: str
    input_types: list[str]
    requires_file: bool = True

    @abstractmethod
    async def run(self, file_path: str | Path, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError
