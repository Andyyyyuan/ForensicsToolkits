from typing import Literal

from pydantic import BaseModel, Field


class LogLevelCounts(BaseModel):
    error: int = 0
    warning: int = 0
    info: int = 0


class LogFragment(BaseModel):
    title: str
    snippet: list[str]


class IpStat(BaseModel):
    ip: str
    count: int


class ParseStrategy(BaseModel):
    source: Literal["ai", "fallback"]
    log_type: str
    overview: str = ""
    error_keywords: list[str] = Field(default_factory=list)
    warning_keywords: list[str] = Field(default_factory=list)
    info_keywords: list[str] = Field(default_factory=list)
    fragment_keywords: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ParsedLogResponse(BaseModel):
    file_id: str
    original_name: str
    total_lines: int
    level_counts: LogLevelCounts
    has_timestamp: bool
    preview_lines: list[str] = Field(default_factory=list)
    possible_ips: list[str] = Field(default_factory=list)
    ip_stats: list[IpStat] = Field(default_factory=list)
    key_fragments: list[LogFragment] = Field(default_factory=list)
    parse_strategy: ParseStrategy


class LogSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    use_regex: bool = False
    case_sensitive: bool = False
    limit: int = Field(default=200, ge=1, le=1000)


class LogSearchMatch(BaseModel):
    line_number: int
    content: str


class LogSearchResponse(BaseModel):
    file_id: str
    query: str
    use_regex: bool
    case_sensitive: bool
    total_matches: int
    matches: list[LogSearchMatch] = Field(default_factory=list)


class AIAnalysisRequest(BaseModel):
    question: str = Field(
        default="请从电子取证和风险研判视角概述这份日志，并指出当前证据能支持与不能支持的结论。",
        min_length=1,
        max_length=2000,
    )


class FindingItem(BaseModel):
    title: str
    evidence: list[str] = Field(default_factory=list)
    explanation: str


class AIAnalysisResult(BaseModel):
    summary: str
    risk_level: Literal["low", "medium", "high"]
    findings: list[FindingItem] = Field(default_factory=list)
    timeline_summary: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AIAnalysisResponse(BaseModel):
    file_id: str
    analysis_source: Literal["ai", "fallback"]
    analysis: AIAnalysisResult


class LogParserStatusResponse(BaseModel):
    ai_configured: bool
    ai_base_url: str | None = None
    ai_chat_model: str | None = None
    ai_reasoner_model: str | None = None
