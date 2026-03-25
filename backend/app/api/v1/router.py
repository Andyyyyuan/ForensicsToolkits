from fastapi import APIRouter

from app.api.v1.tools import router as tools_router


def build_api_router() -> APIRouter:
    api_router = APIRouter()
    api_router.include_router(tools_router, prefix="/tools", tags=["tools"])
    return api_router
