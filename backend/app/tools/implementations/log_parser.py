from pathlib import Path
from typing import Any

from app.schemas.log_parser import IpStat, LogFragment, LogLevelCounts, ParseStrategy
from app.tools.base import BaseTool
from app.tools.log_patterns import IP_PATTERN, TIMESTAMP_PATTERNS
from app.tools.registry import tool_registry


class LogParserTool(BaseTool):
    tool_id = "log_parser"
    name = "日志分析"
    description = "解析文本日志，提取异常片段、IP 线索、时间戳和结构化统计结果。"
    input_types = [".txt", ".log"]

    async def run(self, file_path: str | Path, params: dict[str, Any] | None = None) -> dict[str, Any]:
        path = Path(file_path)
        options = params or {}
        original_name = str(options.get("original_name") or path.name)
        file_id = str(options.get("file_id") or "")
        parse_strategy_data = options.get("parse_strategy")
        if not parse_strategy_data:
            raise ValueError("log_parser 缺少 parse_strategy 参数。")

        parse_strategy = (
            parse_strategy_data
            if isinstance(parse_strategy_data, ParseStrategy)
            else ParseStrategy(**parse_strategy_data)
        )

        text = self.read_text(path)
        lines = text.splitlines()

        level_counts = LogLevelCounts(
            error=self._count_lines(lines, parse_strategy.error_keywords),
            warning=self._count_lines(lines, parse_strategy.warning_keywords),
            info=self._count_lines(lines, parse_strategy.info_keywords),
        )

        return {
            "file_id": file_id,
            "original_name": original_name,
            "total_lines": len(lines),
            "level_counts": level_counts.model_dump(),
            "has_timestamp": self._detect_timestamp(lines),
            "preview_lines": lines[:20],
            "possible_ips": self._extract_ips(lines),
            "ip_stats": [item.model_dump() for item in self._extract_ip_stats(lines)],
            "key_fragments": [
                fragment.model_dump()
                for fragment in self._extract_key_fragments(
                    lines,
                    parse_strategy.error_keywords + parse_strategy.warning_keywords,
                )
            ],
            "parse_strategy": parse_strategy.model_dump(),
        }

    def read_text(self, path: str | Path) -> str:
        raw = Path(path).read_bytes()
        for encoding in ("utf-8", "utf-8-sig", "gb18030", "big5", "utf-16"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")

    def build_sample_lines(self, file_path: str | Path, limit: int = 30) -> list[str]:
        text = self.read_text(file_path)
        return [line.rstrip() for line in text.splitlines()[:limit] if line.strip()]

    def _count_lines(self, lines: list[str], keywords: list[str]) -> int:
        normalized = self._normalize_keywords(keywords)
        if not normalized:
            return 0
        return sum(1 for line in lines if self._line_contains_keywords(line, normalized))

    def _detect_timestamp(self, lines: list[str]) -> bool:
        for line in lines[: min(len(lines), 300)]:
            if any(pattern.search(line) for pattern in TIMESTAMP_PATTERNS):
                return True
        return False

    def _extract_ips(self, lines: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for line in lines:
            for ip in IP_PATTERN.findall(line):
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
                if len(result) >= 50:
                    return result
        return result

    def _extract_ip_stats(self, lines: list[str]) -> list[IpStat]:
        counts: dict[str, int] = {}
        for line in lines:
            for ip in IP_PATTERN.findall(line):
                counts[ip] = counts.get(ip, 0) + 1

        items = [IpStat(ip=ip, count=count) for ip, count in counts.items()]
        items.sort(key=lambda item: (-item.count, item.ip))
        return items[:100]

    def _extract_key_fragments(self, lines: list[str], fragment_keywords: list[str]) -> list[LogFragment]:
        keywords = self._normalize_keywords(fragment_keywords)
        fragments: list[LogFragment] = []
        seen: set[str] = set()
        last_end = -1

        for index, line in enumerate(lines):
            if not self._line_contains_keywords(line, keywords):
                continue

            start = max(index - 1, 0)
            end = min(index + 3, len(lines))
            if start <= last_end:
                continue

            snippet = [item.rstrip() for item in lines[start:end] if item.strip()]
            if not snippet:
                continue

            unique_key = "\n".join(snippet)
            if unique_key in seen:
                continue

            seen.add(unique_key)
            fragments.append(LogFragment(title=f"异常片段 #{len(fragments) + 1}", snippet=snippet))
            last_end = end - 1
            if len(fragments) >= 10:
                break

        return fragments

    def _normalize_keywords(self, keywords: list[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for keyword in keywords:
            value = keyword.strip().lower()
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def _line_contains_keywords(self, line: str, keywords: list[str]) -> bool:
        lower_line = line.lower()
        return any(keyword in lower_line for keyword in keywords)


def register_log_parser_tool() -> None:
    if not tool_registry.has_tool("log_parser"):
        tool_registry.register(LogParserTool())
