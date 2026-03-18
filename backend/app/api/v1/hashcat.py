from fastapi import APIRouter, HTTPException

from app.schemas.tools import HashcatTaskStatusResponse
from app.services.hashcat_service import hashcat_service
from app.services.tool_config_service import ToolDisabledError, tool_config_service

router = APIRouter()


@router.get("/status", response_model=HashcatTaskStatusResponse)
async def get_hashcat_status() -> HashcatTaskStatusResponse:
    try:
        tool_config_service.ensure_enabled("hashcat_gui")
    except ToolDisabledError as exc:
        raise HTTPException(status_code=403, detail=exc.message) from exc

    availability = tool_config_service.get_availability("hashcat_gui")
    return HashcatTaskStatusResponse(
        **hashcat_service.get_status(),
        enabled=availability.enabled,
        disabled_title=availability.disabled_title,
        disabled_message=availability.disabled_message,
    )


@router.post("/stop", response_model=HashcatTaskStatusResponse)
async def stop_hashcat_task() -> HashcatTaskStatusResponse:
    try:
        tool_config_service.ensure_enabled("hashcat_gui")
    except ToolDisabledError as exc:
        raise HTTPException(status_code=403, detail=exc.message) from exc

    availability = tool_config_service.get_availability("hashcat_gui")
    return HashcatTaskStatusResponse(
        **hashcat_service.stop_task(),
        enabled=availability.enabled,
        disabled_title=availability.disabled_title,
        disabled_message=availability.disabled_message,
    )
