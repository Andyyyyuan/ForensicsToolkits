import json
from typing import Any, AsyncIterator

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from app.schemas.file import FileUploadResponse
from app.schemas.tools import (
    AIStatusResponse,
    SqliteBrowserResponse,
    SqliteExportRequest,
    SqliteExportResponse,
    SqlitePreviewRequest,
    SqlitePreviewResponse,
    ToolAIRequest,
    ToolAIResponse,
    ToolMetaResponse,
    ToolRunRequest,
    ToolRunResponse,
)
from app.services.ai_analysis_service import ai_analysis_service
from app.services.db_service import db_service
from app.services.file_service import file_service
from app.services.sqlite_browser_service import sqlite_browser_service
from app.services.tool_config_service import ToolDisabledError, tool_config_service
from app.services.tool_service import run_tool, tool_service

router = APIRouter()
UNIFIED_AI_TOOL_IDS = {"log_parser", "timestamp_parser", "hashcat_gui", "encoding_converter", "hash_tool", "sqlite2csv"}


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


def _build_tool_meta_response(tool) -> ToolMetaResponse:
    availability = tool_config_service.get_availability(tool.tool_id)
    return ToolMetaResponse(
        tool_id=tool.tool_id,
        name=tool.name,
        description=tool.description,
        input_types=tool.input_types,
        requires_file=tool.requires_file,
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
    payload = result.model_dump() if hasattr(result, "model_dump") else result
    return ToolAIResponse(
        tool_id=tool_id,
        mode=mode,
        model=ai_analysis_service.get_model_name(mode) or None,
        source=source,
        reasoning=reasoning,
        result=payload,
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


async def _resolve_parsed_log(file_id: str):
    file_record = _get_file_record_or_404(file_id)
    parsed_data = db_service.get_parsed_result(file_id)
    if parsed_data:
        from app.schemas.log_parser import ParsedLogResponse

        return ParsedLogResponse(**parsed_data)

    from app.services.log_parser_service import log_parser_service

    parsed_result = await log_parser_service.parse_file(file_record)
    db_service.save_parsed_result(file_id, parsed_result.model_dump())
    return parsed_result


async def _resolve_tool_ai_result(payload: ToolAIRequest) -> tuple[str, Any, str]:
    tool_id = payload.tool_id.strip()
    user_input = payload.user_input.strip()

    if tool_id == "log_parser":
        if not payload.file_id:
            raise HTTPException(status_code=400, detail="日志研判需要 file_id。")
        parsed_result = await _resolve_parsed_log(payload.file_id)
        return await ai_analysis_service.analyze_with_meta(
            parsed_result=parsed_result,
            question=user_input,
            mode=payload.mode,
        )

    if tool_id == "timestamp_parser":
        result, source, reasoning = await ai_analysis_service.assist_timestamp_with_meta(user_input, mode=payload.mode)
        return source, result, reasoning

    if tool_id == "hashcat_gui":
        result, source, reasoning = await ai_analysis_service.assist_hashcat_with_meta(
            user_input,
            file_id=payload.file_id,
            context=payload.context,
            mode=payload.mode,
        )
        return source, result, reasoning

    if tool_id == "encoding_converter":
        result, source, reasoning = await ai_analysis_service.assist_encoding_with_meta(user_input, mode=payload.mode)
        return source, result, reasoning

    if tool_id == "hash_tool":
        result, source, reasoning = await ai_analysis_service.assist_hash_result_with_meta(
            user_input,
            context=payload.context,
            mode=payload.mode,
        )
        return source, result, reasoning

    if tool_id == "sqlite2csv":
        result, source, reasoning = await ai_analysis_service.assist_sqlite_result_with_meta(
            user_input,
            context=payload.context,
            mode=payload.mode,
        )
        return source, result, reasoning

    raise HTTPException(status_code=400, detail="当前工具未接入统一 AI 辅助。")


async def _resolve_tool_ai_stream(payload: ToolAIRequest) -> AsyncIterator[dict[str, Any]]:
    tool_id = payload.tool_id.strip()
    user_input = payload.user_input.strip()

    if tool_id == "log_parser":
        if not payload.file_id:
            raise HTTPException(status_code=400, detail="日志研判需要 file_id。")
        parsed_result = await _resolve_parsed_log(payload.file_id)
        async for item in ai_analysis_service.stream_log_analysis(
            parsed_result=parsed_result,
            question=user_input,
            mode=payload.mode,
        ):
            yield item
        return

    if tool_id == "timestamp_parser":
        iterator = ai_analysis_service.stream_timestamp_assist(user_input, mode=payload.mode)
    elif tool_id == "hashcat_gui":
        iterator = ai_analysis_service.stream_hashcat_assist(
            user_input,
            file_id=payload.file_id,
            context=payload.context,
            mode=payload.mode,
        )
    elif tool_id == "hash_tool":
        iterator = ai_analysis_service.stream_hash_result_assist(
            user_input,
            context=payload.context,
            mode=payload.mode,
        )
    elif tool_id == "sqlite2csv":
        iterator = ai_analysis_service.stream_sqlite_result_assist(
            user_input,
            context=payload.context,
            mode=payload.mode,
        )
    elif tool_id == "encoding_converter":
        iterator = ai_analysis_service.stream_encoding_assist(user_input, mode=payload.mode)
    else:
        raise HTTPException(status_code=400, detail="当前工具未接入统一 AI 辅助。")

    async for item in iterator:
        yield item


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
    _ensure_tool_enabled(tool_id)
    if tool_id not in UNIFIED_AI_TOOL_IDS:
        raise HTTPException(status_code=400, detail="当前工具未接入统一 AI 辅助。")
    source, result, reasoning = await _resolve_tool_ai_result(payload)
    return _build_tool_ai_response(tool_id=tool_id, mode=payload.mode, source=source, reasoning=reasoning, result=result)


@router.post("/ai/assist/stream")
async def assist_tool_with_ai_stream(payload: ToolAIRequest) -> StreamingResponse:
    tool_id = payload.tool_id.strip()
    _ensure_tool_enabled(tool_id)
    if tool_id not in UNIFIED_AI_TOOL_IDS:
        raise HTTPException(status_code=400, detail="当前工具未接入统一 AI 辅助。")

    async def event_stream():
        async for item in _resolve_tool_ai_stream(payload):
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


@router.post("/upload", response_model=FileUploadResponse)
async def upload_tool_file(tool_id: str = Form(...), file: UploadFile = File(...)) -> FileUploadResponse:
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


@router.get("/sqlite2csv/browser/{file_id}", response_model=SqliteBrowserResponse)
async def inspect_sqlite_database(file_id: str) -> SqliteBrowserResponse:
    file_record = _get_file_record_or_404(file_id)
    try:
        _ensure_tool_enabled("sqlite2csv")
        return sqlite_browser_service.inspect_database(
            file_path=file_record["file_path"],
            file_id=file_id,
            database_name=file_record["original_name"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sqlite2csv/browser/{file_id}/preview", response_model=SqlitePreviewResponse)
async def preview_sqlite_table(file_id: str, payload: SqlitePreviewRequest) -> SqlitePreviewResponse:
    file_record = _get_file_record_or_404(file_id)
    try:
        _ensure_tool_enabled("sqlite2csv")
        return sqlite_browser_service.preview_table(file_record["file_path"], payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sqlite2csv/browser/{file_id}/export", response_model=SqliteExportResponse)
async def export_sqlite_table(file_id: str, payload: SqliteExportRequest) -> SqliteExportResponse:
    file_record = _get_file_record_or_404(file_id)
    try:
        _ensure_tool_enabled("sqlite2csv")
        return sqlite_browser_service.export_table(file_record["file_path"], payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{tool_id}/run", response_model=ToolRunResponse)
async def run_registered_tool_without_file(tool_id: str, payload: ToolRunRequest) -> ToolRunResponse:
    tool = _get_tool_or_404(tool_id)
    if tool.requires_file:
        raise HTTPException(status_code=400, detail=f"工具 {tool_id} 需要先上传文件。")
    return await _run_registered_tool(tool_id=tool_id, file_id=None, file_path="", params=payload.params)


@router.post("/{tool_id}/run/{file_id}", response_model=ToolRunResponse)
async def run_registered_tool_with_file(tool_id: str, file_id: str, payload: ToolRunRequest) -> ToolRunResponse:
    file_record = _get_file_record_or_404(file_id)
    tool = _get_tool_or_404(tool_id)
    if not tool.requires_file:
        raise HTTPException(status_code=400, detail=f"工具 {tool_id} 无需上传文件，请直接调用无文件执行接口。")
    return await _run_registered_tool(
        tool_id=tool_id,
        file_id=file_id,
        file_path=file_record["file_path"],
        params=payload.params,
    )
