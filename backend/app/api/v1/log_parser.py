from fastapi import APIRouter, File, HTTPException, UploadFile

from app.schemas.file import FileUploadResponse
from app.schemas.log_parser import (
    LogParserStatusResponse,
    LogSearchRequest,
    LogSearchResponse,
    ParsedLogResponse,
)
from app.services.ai_analysis_service import ai_analysis_service
from app.services.db_service import db_service
from app.services.file_service import file_service
from app.services.log_parser_service import log_parser_service
from app.services.tool_config_service import ToolDisabledError, tool_config_service

router = APIRouter()


def _log_upload_max_size_bytes() -> int:
    return file_service.env_int("TOOL_LOG_PARSER_UPLOAD_MAX_SIZE_BYTES", 10 * 1024 * 1024)


@router.get("/status", response_model=LogParserStatusResponse)
async def get_log_parser_status() -> LogParserStatusResponse:
    return LogParserStatusResponse(
        ai_configured=ai_analysis_service.is_configured(),
        ai_base_url=ai_analysis_service.api_base_url or None,
        ai_chat_model=ai_analysis_service.chat_model or None,
        ai_reasoner_model=ai_analysis_service.reasoner_model or None,
    )


@router.post("/upload", response_model=FileUploadResponse)
async def upload_log_file(file: UploadFile = File(...)) -> FileUploadResponse:
    try:
        tool_config_service.ensure_enabled("log_parser")
    except ToolDisabledError as exc:
        raise HTTPException(status_code=403, detail=exc.message) from exc

    saved_file = await file_service.save_upload(
        file=file,
        allowed_suffixes={".txt", ".log"},
        max_size_bytes=_log_upload_max_size_bytes(),
    )
    return FileUploadResponse(**saved_file)


@router.post("/parse/{file_id}", response_model=ParsedLogResponse)
async def parse_log(file_id: str) -> ParsedLogResponse:
    file_record = db_service.get_file(file_id)
    if not file_record:
        raise HTTPException(status_code=404, detail="文件不存在或尚未上传。")

    try:
        tool_config_service.ensure_enabled("log_parser")
    except ToolDisabledError as exc:
        raise HTTPException(status_code=403, detail=exc.message) from exc

    parsed_result = await log_parser_service.parse_file(file_record)
    db_service.save_parsed_result(file_id, parsed_result.model_dump())
    return parsed_result


@router.post("/search/{file_id}", response_model=LogSearchResponse)
async def search_log(file_id: str, payload: LogSearchRequest) -> LogSearchResponse:
    file_record = db_service.get_file(file_id)
    if not file_record:
        raise HTTPException(status_code=404, detail="文件不存在或尚未上传。")

    try:
        tool_config_service.ensure_enabled("log_parser")
        return await log_parser_service.search_file(
            file_record=file_record,
            query=payload.query,
            use_regex=payload.use_regex,
            case_sensitive=payload.case_sensitive,
            limit=payload.limit,
        )
    except ToolDisabledError as exc:
        raise HTTPException(status_code=403, detail=exc.message) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"日志搜索失败：{exc}") from exc
