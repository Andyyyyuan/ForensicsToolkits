import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


def _resolve_path(env_name: str, default: Path) -> Path:
    value = os.getenv(env_name, "").strip()
    if not value:
        return default

    path = Path(value)
    return path if path.is_absolute() else BASE_DIR / path


def get_storage_dir() -> Path:
    return _resolve_path("APP_STORAGE_DIR", BASE_DIR / "storage")


def get_data_dir() -> Path:
    return _resolve_path("APP_DATA_DIR", get_storage_dir() / "data")


def get_upload_dir() -> Path:
    return _resolve_path("APP_UPLOAD_DIR", get_storage_dir() / "uploads")


def get_log_dir() -> Path:
    return _resolve_path("APP_LOG_DIR", get_storage_dir() / "logs")


def get_report_dir() -> Path:
    return _resolve_path("APP_REPORT_DIR", get_storage_dir() / "reports")


def get_db_path() -> Path:
    return _resolve_path("APP_DB_PATH", get_storage_dir() / "app.db")


def ensure_runtime_dirs() -> None:
    for path in (
        get_storage_dir(),
        get_data_dir(),
        get_upload_dir(),
        get_log_dir(),
        get_report_dir(),
    ):
        path.mkdir(parents=True, exist_ok=True)

    get_db_path().parent.mkdir(parents=True, exist_ok=True)
