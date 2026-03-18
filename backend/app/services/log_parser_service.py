from pathlib import Path
import re
from typing import Any

from app.schemas.log_parser import LogSearchMatch, LogSearchResponse, ParsedLogResponse
from app.services.ai_analysis_service import ai_analysis_service
from app.services.tool_service import tool_service


class LogParserService:
    async def parse_file(self, file_record: dict[str, Any]) -> ParsedLogResponse:
        file_path = Path(file_record["file_path"])
        log_parser_tool = tool_service.get_tool("log_parser")

        sample_lines = log_parser_tool.build_sample_lines(file_path=file_path)
        parse_strategy = await ai_analysis_service.suggest_parse_strategy(
            file_name=file_record["original_name"],
            sample_lines=sample_lines,
        )

        result = await tool_service.run_tool(
            tool_id="log_parser",
            file_path=file_path,
            params={
                "file_id": file_record["file_id"],
                "original_name": file_record["original_name"],
                "parse_strategy": parse_strategy.model_dump(),
            },
        )
        return ParsedLogResponse(**result)

    async def search_file(
        self,
        file_record: dict[str, Any],
        query: str,
        use_regex: bool = False,
        case_sensitive: bool = False,
        limit: int = 200,
    ) -> LogSearchResponse:
        file_path = Path(file_record["file_path"])
        log_parser_tool = tool_service.get_tool("log_parser")
        text = log_parser_tool.read_text(file_path)
        lines = text.splitlines()

        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(query if use_regex else re.escape(query), flags=flags)

        matches: list[LogSearchMatch] = []
        total_matches = 0
        for index, line in enumerate(lines, start=1):
            if not pattern.search(line):
                continue
            total_matches += 1
            if len(matches) < limit:
                matches.append(LogSearchMatch(line_number=index, content=line.rstrip()))

        return LogSearchResponse(
            file_id=file_record["file_id"],
            query=query,
            use_regex=use_regex,
            case_sensitive=case_sensitive,
            total_matches=total_matches,
            matches=matches,
        )


log_parser_service = LogParserService()
