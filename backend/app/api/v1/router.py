from fastapi import APIRouter

from app.api.v1.hashcat import router as hashcat_router
from app.api.v1.log_parser import router as log_parser_router
from app.api.v1.tools import router as tools_router
from app.services.tool_config_service import tool_config_service


def build_api_router() -> APIRouter:
    api_router = APIRouter()
    if tool_config_service.get_availability("hashcat_gui").enabled:
        api_router.include_router(hashcat_router, prefix="/hashcat", tags=["hashcat"])
    api_router.include_router(log_parser_router, prefix="/log-parser", tags=["log-parser"])
    api_router.include_router(tools_router, prefix="/tools", tags=["tools"])
    return api_router
