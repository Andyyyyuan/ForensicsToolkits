from typing import Any, Literal

from pydantic import BaseModel, Field


class ToolMetaResponse(BaseModel):
    tool_id: str
    name: str
    description: str
    input_types: list[str] = Field(default_factory=list)
    requires_file: bool = True
    supports_ai: bool = False
    actions: list[str] = Field(default_factory=list)
    enabled: bool = True
    disabled_title: str | None = None
    disabled_message: str | None = None


class ToolExecutionRequest(BaseModel):
    file_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class ToolRunResponse(BaseModel):
    tool_id: str
    file_id: str | None = None
    result: dict[str, Any]


class ToolActionResponse(BaseModel):
    tool_id: str
    action: str
    file_id: str | None = None
    result: Any


class SqliteTableColumnResponse(BaseModel):
    name: str
    type: str
    not_null: bool
    default_value: str | None = None
    is_primary_key: bool = False


class SqliteTableInfoResponse(BaseModel):
    table_name: str
    row_count: int
    columns: list[SqliteTableColumnResponse] = Field(default_factory=list)
    schema_sql: str | None = None


class SqliteBrowserResponse(BaseModel):
    file_id: str
    database_name: str
    tables: list[SqliteTableInfoResponse] = Field(default_factory=list)


class SqlitePreviewFilterRequest(BaseModel):
    column: str = Field(min_length=1, max_length=255)
    operator: Literal["contains", "equals", "starts_with", "ends_with", "gt", "gte", "lt", "lte", "is_null", "not_null"] = "contains"
    value: str | None = None


class SqlitePreviewRequest(BaseModel):
    table_name: str = Field(min_length=1, max_length=255)
    selected_columns: list[str] = Field(default_factory=list)
    filters: list[SqlitePreviewFilterRequest] = Field(default_factory=list)
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class SqlitePreviewResponse(BaseModel):
    table_name: str
    selected_columns: list[str] = Field(default_factory=list)
    available_columns: list[SqliteTableColumnResponse] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    total_rows: int
    returned_rows: int


class SqliteExportRequest(BaseModel):
    table_name: str = Field(min_length=1, max_length=255)
    selected_columns: list[str] = Field(default_factory=list)
    filters: list[SqlitePreviewFilterRequest] = Field(default_factory=list)
    include_header: bool = True
    delimiter: Literal[",", ";", "\\t", "|"] = ","


class SqliteExportResponse(BaseModel):
    table_name: str
    csv_name: str
    csv_url: str
    row_count: int
    columns: list[str] = Field(default_factory=list)


class AIStatusResponse(BaseModel):
    configured: bool
    chat_model: str | None = None
    reasoner_model: str | None = None


class ToolAIRequest(BaseModel):
    tool_id: str = Field(min_length=1, max_length=100)
    user_input: str = Field(min_length=1, max_length=8000)
    mode: Literal["chat", "reasoner"] = "chat"
    file_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ToolAIResponse(BaseModel):
    tool_id: str
    mode: Literal["chat", "reasoner"]
    model: str | None = None
    source: Literal["ai", "fallback"]
    reasoning: str = ""
    result: dict[str, Any]


class HashcatHashModeResponse(BaseModel):
    mode: int
    name: str
    category: str
    label: str


class HashcatTaskStatusResponse(BaseModel):
    enabled: bool = True
    disabled_title: str | None = None
    disabled_message: str | None = None
    configured: bool
    binary_path: str | None = None
    binary_source: str | None = None
    detected_platform: str
    bundle_dir: str | None = None
    bundled_binary_path: str | None = None
    wordlists_dir: str | None = None
    runtime_dir: str | None = None
    default_wordlist_path: str | None = None
    default_wordlist_name: str | None = None
    running: bool
    task_id: str | None = None
    pid: int | None = None
    command: list[str] = Field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    hash_file: str | None = None
    result_file: str | None = None
    result_lines: list[str] = Field(default_factory=list)
    output_tail: list[str] = Field(default_factory=list)
