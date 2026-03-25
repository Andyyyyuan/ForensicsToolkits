import json
from typing import Any, AsyncIterator, Awaitable, Callable

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from app.schemas.file import FileUploadResponse
from app.schemas.log_parser import LogSearchRequest, ParsedLogResponse
from app.schemas.tools import (
    AIStatusResponse,
    SqliteExportRequest,
    SqlitePreviewRequest,
    ToolAIRequest,
    ToolAIResponse,
    ToolActionResponse,
    ToolExecutionRequest,
    ToolMetaResponse,
    ToolRunResponse,
)
from app.services.ai_analysis_service import ai_analysis_service
from app.services.db_service import db_service
from app.services.file_service import file_service
from app.services.hashcat_service import hashcat_service
from app.services.log_parser_service import log_parser_service
from app.services.sqlite_browser_service import sqlite_browser_service
from app.services.tool_config_service import ToolDisabledError, tool_config_service
from app.services.tool_service import run_tool, tool_service

router = APIRouter()

ToolActionHandler = Callable[[ToolExecutionRequest], Awaitable[Any]]
ToolAIResolver = Callable[[ToolAIRequest], Awaitable[tuple[str, Any, str]]]
ToolAIStreamResolver = Callable[[ToolAIRequest], AsyncIterator[dict[str, Any]]]


def _serialize(value: Any) -> Any:
    return value.model_dump() if hasattr(value, "model_dump") else value


def _ensure_tool_enabled(tool_id: str) -> None:
    try:
        tool_config_service.ensure_enabled(tool_id)
    except ToolDisabledError as exc:
        raise HTTPException(status_code=403, detail=exc.message) from exc


def _get_tool_or_404(tool_id: str):
    try:
        return tool_service.get_tool(tool_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=exc.args[0]) from exc


def _get_file_record_or_404(file_id: str) -> dict[str, Any]:
    file_record = db_service.get_file(file_id)
    if not file_record:
        raise HTTPException(status_code=404, detail="文件不存在或尚未上传。")
    return file_record


def _require_file_record(file_id: str | None, error_message: str = "当前操作需要 file_id。") -> dict[str, Any]:
    if not file_id:
        raise HTTPException(status_code=400, detail=error_message)
    return _get_file_record_or_404(file_id)


def _build_tool_meta_response(tool) -> ToolMetaResponse:
    availability = tool_config_service.get_availability(tool.tool_id)
    return ToolMetaResponse(
        tool_id=tool.tool_id,
        name=tool.name,
        description=tool.description,
        input_types=tool.input_types,
        requires_file=tool.requires_file,
        supports_ai=tool.tool_id in TOOL_AI_RESULT_RESOLVERS,
        actions=sorted({*TOOL_GET_ACTION_HANDLERS.get(tool.tool_id, {}), *TOOL_POST_ACTION_HANDLERS.get(tool.tool_id, {})}),
        enabled=availability.enabled,
        disabled_title=availability.disabled_title,
        disabled_message=availability.disabled_message,
    )


def _build_tool_ai_response(
    *,
    tool_id: str,
    mode: str,
    source: str,
    reasoning: str,
    result: Any,
) -> ToolAIResponse:
    return ToolAIResponse(
        tool_id=tool_id,
        mode=mode,
        model=ai_analysis_service.get_model_name(mode) or None,
        source=source,
        reasoning=reasoning,
        result=_serialize(result),
    )


def _upload_constraints(tool_id: str) -> tuple[set[str] | None, int]:
    normalized = tool_id.upper().replace("-", "_")
    tool = _get_tool_or_404(tool_id)
    allowed_suffixes = None if "*" in tool.input_types else {suffix.lower() for suffix in tool.input_types}

    if tool_id == "hash_tool":
        max_size = file_service.env_int(
            "TOOL_HASH_TOOL_UPLOAD_MAX_SIZE_BYTES",
            file_service.env_int("TOOL_HASH_TOOL_MAX_SIZE_BYTES", 1048576),
        )
        return allowed_suffixes, max_size

    if tool_id == "sqlite2csv":
        return allowed_suffixes, file_service.env_int(f"TOOL_{normalized}_UPLOAD_MAX_SIZE_BYTES", 64 * 1024 * 1024)

    if tool_id == "hashcat_gui":
        return allowed_suffixes, file_service.env_int(f"TOOL_{normalized}_UPLOAD_MAX_SIZE_BYTES", 5 * 1024 * 1024)

    return allowed_suffixes, file_service.env_int(f"TOOL_{normalized}_UPLOAD_MAX_SIZE_BYTES", file_service.default_max_upload_bytes())


async def _resolve_parsed_log(file_id: str) -> ParsedLogResponse:
    file_record = _get_file_record_or_404(file_id)
    parsed_data = db_service.get_parsed_result(file_id)
    if parsed_data:
        return ParsedLogResponse(**parsed_data)

    parsed_result = await log_parser_service.parse_file(file_record)
    db_service.save_parsed_result(file_id, parsed_result.model_dump())
    return parsed_result


async def _run_registered_tool(
    *,
    tool_id: str,
    file_id: str | None,
    file_path: str,
    params: dict[str, Any],
) -> ToolRunResponse:
    _ensure_tool_enabled(tool_id)
    try:
        result = await run_tool(tool_id=tool_id, file_path=file_path, params=params)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ToolRunResponse(tool_id=tool_id, file_id=file_id, result=result)


async def _assist_log_parser(payload: ToolAIRequest) -> tuple[str, Any, str]:
    if not payload.file_id:
        raise HTTPException(status_code=400, detail="日志研判需要 file_id。")
    parsed_result = await _resolve_parsed_log(payload.file_id)
    return await ai_analysis_service.analyze_with_meta(
        parsed_result=parsed_result,
        question=payload.user_input.strip(),
        mode=payload.mode,
    )


async def _assist_timestamp(payload: ToolAIRequest) -> tuple[str, Any, str]:
    result, source, reasoning = await ai_analysis_service.assist_timestamp_with_meta(payload.user_input.strip(), mode=payload.mode)
    return source, result, reasoning


async def _assist_hashcat(payload: ToolAIRequest) -> tuple[str, Any, str]:
    result, source, reasoning = await ai_analysis_service.assist_hashcat_with_meta(
        payload.user_input.strip(),
        file_id=payload.file_id,
        context=payload.context,
        mode=payload.mode,
    )
    return source, result, reasoning


async def _assist_encoding(payload: ToolAIRequest) -> tuple[str, Any, str]:
    result, source, reasoning = await ai_analysis_service.assist_encoding_with_meta(payload.user_input.strip(), mode=payload.mode)
    return source, result, reasoning


async def _assist_hash_tool(payload: ToolAIRequest) -> tuple[str, Any, str]:
    result, source, reasoning = await ai_analysis_service.assist_hash_result_with_meta(
        payload.user_input.strip(),
        context=payload.context,
        mode=payload.mode,
    )
    return source, result, reasoning


async def _assist_sqlite(payload: ToolAIRequest) -> tuple[str, Any, str]:
    result, source, reasoning = await ai_analysis_service.assist_sqlite_result_with_meta(
        payload.user_input.strip(),
        context=payload.context,
        mode=payload.mode,
    )
    return source, result, reasoning


async def _stream_assist_log_parser(payload: ToolAIRequest) -> AsyncIterator[dict[str, Any]]:
    if not payload.file_id:
        raise HTTPException(status_code=400, detail="日志研判需要 file_id。")
    parsed_result = await _resolve_parsed_log(payload.file_id)
    async for item in ai_analysis_service.stream_log_analysis(
        parsed_result=parsed_result,
        question=payload.user_input.strip(),
        mode=payload.mode,
    ):
        yield item


async def _stream_assist_timestamp(payload: ToolAIRequest) -> AsyncIterator[dict[str, Any]]:
    async for item in ai_analysis_service.stream_timestamp_assist(payload.user_input.strip(), mode=payload.mode):
        yield item


async def _stream_assist_hashcat(payload: ToolAIRequest) -> AsyncIterator[dict[str, Any]]:
    async for item in ai_analysis_service.stream_hashcat_assist(
        payload.user_input.strip(),
        file_id=payload.file_id,
        context=payload.context,
        mode=payload.mode,
    ):
        yield item


async def _stream_assist_encoding(payload: ToolAIRequest) -> AsyncIterator[dict[str, Any]]:
    async for item in ai_analysis_service.stream_encoding_assist(payload.user_input.strip(), mode=payload.mode):
        yield item


async def _stream_assist_hash_tool(payload: ToolAIRequest) -> AsyncIterator[dict[str, Any]]:
    async for item in ai_analysis_service.stream_hash_result_assist(
        payload.user_input.strip(),
        context=payload.context,
        mode=payload.mode,
    ):
        yield item


async def _stream_assist_sqlite(payload: ToolAIRequest) -> AsyncIterator[dict[str, Any]]:
    async for item in ai_analysis_service.stream_sqlite_result_assist(
        payload.user_input.strip(),
        context=payload.context,
        mode=payload.mode,
    ):
        yield item


async def _action_log_parse(payload: ToolExecutionRequest) -> Any:
    file_record = _require_file_record(payload.file_id, "日志解析需要 file_id。")
    return await log_parser_service.parse_file(file_record)


async def _action_log_search(payload: ToolExecutionRequest) -> Any:
    file_record = _require_file_record(payload.file_id, "日志搜索需要 file_id。")
    request = LogSearchRequest(**payload.params)
    try:
        return await log_parser_service.search_file(
            file_record=file_record,
            query=request.query,
            use_regex=request.use_regex,
            case_sensitive=request.case_sensitive,
            limit=request.limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"日志搜索失败：{exc}") from exc


async def _action_sqlite_inspect(payload: ToolExecutionRequest) -> Any:
    file_record = _require_file_record(payload.file_id, "SQLite 浏览需要 file_id。")
    try:
        return sqlite_browser_service.inspect_database(
            file_path=file_record["file_path"],
            file_id=file_record["file_id"],
            database_name=file_record["original_name"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _action_sqlite_preview(payload: ToolExecutionRequest) -> Any:
    file_record = _require_file_record(payload.file_id, "SQLite 预览需要 file_id。")
    try:
        return sqlite_browser_service.preview_table(
            file_record["file_path"],
            SqlitePreviewRequest(**payload.params),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _action_sqlite_export(payload: ToolExecutionRequest) -> Any:
    file_record = _require_file_record(payload.file_id, "SQLite 导出需要 file_id。")
    try:
        return sqlite_browser_service.export_table(
            file_record["file_path"],
            SqliteExportRequest(**payload.params),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _action_hashcat_stop(_: ToolExecutionRequest) -> Any:
    availability = tool_config_service.get_availability("hashcat_gui")
    return {
        **hashcat_service.stop_task(),
        "enabled": availability.enabled,
        "disabled_title": availability.disabled_title,
        "disabled_message": availability.disabled_message,
    }


async def _action_hashcat_status(_: ToolExecutionRequest) -> Any:
    availability = tool_config_service.get_availability("hashcat_gui")
    return {
        **hashcat_service.get_status(),
        "enabled": availability.enabled,
        "disabled_title": availability.disabled_title,
        "disabled_message": availability.disabled_message,
    }


async def _action_hashcat_hash_modes(_: ToolExecutionRequest) -> Any:
    return hashcat_service.get_hash_modes()


TOOL_AI_RESULT_RESOLVERS: dict[str, ToolAIResolver] = {
    "log_parser": _assist_log_parser,
    "timestamp_parser": _assist_timestamp,
    "hashcat_gui": _assist_hashcat,
    "encoding_converter": _assist_encoding,
    "hash_tool": _assist_hash_tool,
    "sqlite2csv": _assist_sqlite,
}

TOOL_AI_STREAM_RESOLVERS: dict[str, ToolAIStreamResolver] = {
    "log_parser": _stream_assist_log_parser,
    "timestamp_parser": _stream_assist_timestamp,
    "hashcat_gui": _stream_assist_hashcat,
    "encoding_converter": _stream_assist_encoding,
    "hash_tool": _stream_assist_hash_tool,
    "sqlite2csv": _stream_assist_sqlite,
}

TOOL_GET_ACTION_HANDLERS: dict[str, dict[str, ToolActionHandler]] = {
    "hashcat_gui": {
        "status": _action_hashcat_status,
        "hash-modes": _action_hashcat_hash_modes,
    },
}

TOOL_POST_ACTION_HANDLERS: dict[str, dict[str, ToolActionHandler]] = {
    "log_parser": {
        "parse": _action_log_parse,
        "search": _action_log_search,
    },
    "sqlite2csv": {
        "inspect": _action_sqlite_inspect,
        "preview": _action_sqlite_preview,
        "export": _action_sqlite_export,
    },
    "hashcat_gui": {
        "stop": _action_hashcat_stop,
    },
}


def _resolve_action_handler(
    *,
    tool_id: str,
    action: str,
    registry: dict[str, dict[str, ToolActionHandler]],
) -> ToolActionHandler:
    handler = registry.get(tool_id, {}).get(action)
    if handler is None:
        raise HTTPException(status_code=404, detail=f"工具 {tool_id} 不支持动作 {action}。")
    return handler


@router.get("", response_model=list[ToolMetaResponse])
async def list_registered_tools() -> list[ToolMetaResponse]:
    return [_build_tool_meta_response(tool) for tool in tool_service.list_tools()]


@router.get("/ai/status", response_model=AIStatusResponse)
async def get_ai_status() -> AIStatusResponse:
    return AIStatusResponse(
        configured=ai_analysis_service.is_configured(),
        chat_model=ai_analysis_service.chat_model or None,
        reasoner_model=ai_analysis_service.reasoner_model or None,
    )


@router.post("/ai/assist", response_model=ToolAIResponse)
async def assist_tool_with_ai(payload: ToolAIRequest) -> ToolAIResponse:
    tool_id = payload.tool_id.strip()
    _get_tool_or_404(tool_id)
    _ensure_tool_enabled(tool_id)
    resolver = TOOL_AI_RESULT_RESOLVERS.get(tool_id)
    if resolver is None:
        raise HTTPException(status_code=400, detail="当前工具未接入统一 AI 辅助。")
    source, result, reasoning = await resolver(payload)
    return _build_tool_ai_response(tool_id=tool_id, mode=payload.mode, source=source, reasoning=reasoning, result=result)


@router.post("/ai/assist/stream")
async def assist_tool_with_ai_stream(payload: ToolAIRequest) -> StreamingResponse:
    tool_id = payload.tool_id.strip()
    _get_tool_or_404(tool_id)
    _ensure_tool_enabled(tool_id)
    resolver = TOOL_AI_STREAM_RESOLVERS.get(tool_id)
    if resolver is None:
        raise HTTPException(status_code=400, detail="当前工具未接入统一 AI 辅助。")

    async def event_stream() -> AsyncIterator[str]:
        async for item in resolver(payload):
            yield json.dumps(item, ensure_ascii=False) + "\n"

    return StreamingResponse(
        event_stream(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/{tool_id}/upload", response_model=FileUploadResponse)
async def upload_tool_file(tool_id: str, file: UploadFile = File(...)) -> FileUploadResponse:
    normalized_tool_id = tool_id.strip()
    _get_tool_or_404(normalized_tool_id)
    _ensure_tool_enabled(normalized_tool_id)
    allowed_suffixes, max_size_bytes = _upload_constraints(normalized_tool_id)
    saved_file = await file_service.save_upload(
        file=file,
        allowed_suffixes=allowed_suffixes,
        max_size_bytes=max_size_bytes,
    )
    return FileUploadResponse(**saved_file)


@router.post("/{tool_id}/run", response_model=ToolRunResponse)
async def run_registered_tool(tool_id: str, payload: ToolExecutionRequest) -> ToolRunResponse:
    normalized_tool_id = tool_id.strip()
    tool = _get_tool_or_404(normalized_tool_id)

    file_id = payload.file_id
    file_path = ""
    if file_id:
        file_record = _get_file_record_or_404(file_id)
        file_path = file_record["file_path"]
    elif tool.requires_file:
        raise HTTPException(status_code=400, detail=f"工具 {normalized_tool_id} 需要先上传文件。")

    return await _run_registered_tool(
        tool_id=normalized_tool_id,
        file_id=file_id,
        file_path=file_path,
        params=payload.params,
    )


@router.get("/{tool_id}/actions/{action}", response_model=ToolActionResponse)
async def get_tool_action(tool_id: str, action: str) -> ToolActionResponse:
    normalized_tool_id = tool_id.strip()
    normalized_action = action.strip()
    _get_tool_or_404(normalized_tool_id)
    _ensure_tool_enabled(normalized_tool_id)
    handler = _resolve_action_handler(tool_id=normalized_tool_id, action=normalized_action, registry=TOOL_GET_ACTION_HANDLERS)
    result = await handler(ToolExecutionRequest())
    return ToolActionResponse(tool_id=normalized_tool_id, action=normalized_action, result=_serialize(result))


@router.post("/{tool_id}/actions/{action}", response_model=ToolActionResponse)
async def run_tool_action(tool_id: str, action: str, payload: ToolExecutionRequest) -> ToolActionResponse:
    normalized_tool_id = tool_id.strip()
    normalized_action = action.strip()
    _get_tool_or_404(normalized_tool_id)
    _ensure_tool_enabled(normalized_tool_id)
    handler = _resolve_action_handler(tool_id=normalized_tool_id, action=normalized_action, registry=TOOL_POST_ACTION_HANDLERS)
    result = await handler(payload)
    return ToolActionResponse(
        tool_id=normalized_tool_id,
        action=normalized_action,
        file_id=payload.file_id,
        result=_serialize(result),
    )
