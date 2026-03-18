import hashlib
import os
from pathlib import Path
from typing import Any

from app.tools.base import BaseTool
from app.tools.registry import tool_registry

PREFERRED_HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "sm3")
SUPPORTED_HASH_ALGORITHMS = tuple(
    algorithm for algorithm in PREFERRED_HASH_ALGORITHMS if algorithm in hashlib.algorithms_available
)


class HashTool(BaseTool):
    tool_id = "hash_tool"
    name = "文件哈希"
    description = "为上传文件计算 MD5、SHA1、SHA256、SHA512、SM3 等常见摘要。"
    input_types = ["*"]

    async def run(self, file_path: str | Path, params: dict[str, Any] | None = None) -> dict[str, Any]:
        path = Path(file_path)
        options = params or {}
        self._validate_file_size(path)
        algorithms = self._normalize_algorithms(options.get("algorithms"))

        hashers = {name: hashlib.new(name) for name in algorithms}
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                for hasher in hashers.values():
                    hasher.update(chunk)

        return {
            "file_name": path.name,
            "file_size": path.stat().st_size,
            "algorithms": algorithms,
            "available_algorithms": list(SUPPORTED_HASH_ALGORITHMS),
            "hashes": {name: hasher.hexdigest() for name, hasher in hashers.items()},
        }

    def _validate_file_size(self, path: Path) -> None:
        max_size = self._max_file_size_bytes()
        if max_size <= 0:
            return
        file_size = path.stat().st_size
        if file_size > max_size:
            raise ValueError(f"文件过大。当前大小 {file_size} 字节，超过限制 {max_size} 字节。")

    def _max_file_size_bytes(self) -> int:
        raw_value = os.getenv("TOOL_HASH_TOOL_MAX_SIZE_BYTES", "1048576").strip()
        try:
            return int(raw_value)
        except ValueError:
            return 1048576

    def _normalize_algorithms(self, value: Any) -> list[str]:
        if not value:
            return list(SUPPORTED_HASH_ALGORITHMS)
        if not isinstance(value, list):
            raise ValueError("algorithms 必须是哈希算法名称列表。")

        normalized: list[str] = []
        seen: set[str] = set()
        for item in value:
            algorithm = str(item).strip().lower()
            if algorithm not in SUPPORTED_HASH_ALGORITHMS:
                raise ValueError(f"不支持的哈希算法：{algorithm}")
            if algorithm in seen:
                continue
            seen.add(algorithm)
            normalized.append(algorithm)

        return normalized or list(SUPPORTED_HASH_ALGORITHMS)


def register_hash_tool() -> None:
    if not tool_registry.has_tool("hash_tool"):
        tool_registry.register(HashTool())
