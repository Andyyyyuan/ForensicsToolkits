import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.core.paths import ensure_runtime_dirs, get_report_dir
from app.services.db_service import db_service

BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent

# 先加载项目根目录 .env 作为统一主配置，再允许 backend/.env 作为本地开发覆盖层。
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(BASE_DIR / ".env", override=True)


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _common_local_origins() -> list[str]:
    frontend_port = os.getenv("FRONTEND_PORT", "8080").strip() or "8080"
    candidates = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        f"http://localhost:{frontend_port}",
        f"http://127.0.0.1:{frontend_port}",
    ]
    return _dedupe_keep_order(candidates)


def _configure_cors(app: FastAPI) -> None:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    allow_all = _env_flag("CORS_ALLOW_ALL", default=app_env == "development")
    allow_origins = _env_list("CORS_ALLOW_ORIGINS")

    if allow_all:
        app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=r"https?://.*",
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        return

    if not allow_origins:
        allow_origins = _common_local_origins()
    else:
        allow_origins = _dedupe_keep_order([*allow_origins, *_common_local_origins()])

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="智能电子取证工具平台",
        version="0.1.0",
        description="面向本地部署场景的电子取证工具平台，提供日志分析、文件哈希、SQLite 导出、时间戳转换与 Hashcat 图形化能力。",
    )

    _configure_cors(app)

    ensure_runtime_dirs()
    db_service.initialize()

    app.mount("/storage/reports", StaticFiles(directory=get_report_dir()), name="storage-reports")

    from app.api.v1.router import build_api_router

    app.include_router(build_api_router(), prefix="/api/v1")

    @app.get("/health", tags=["health"])
    async def health_check() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
