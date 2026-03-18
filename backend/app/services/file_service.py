import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from fastapi import HTTPException, UploadFile

from app.core.paths import get_upload_dir
from app.services.db_service import db_service


class FileService:
    def __init__(self, upload_dir: str | Path | None = None) -> None:
        self.upload_dir = Path(upload_dir) if upload_dir is not None else get_upload_dir()
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    async def save_upload(
        self,
        file: UploadFile,
        allowed_suffixes: Iterable[str] | None = None,
        max_size_bytes: int | None = None,
    ) -> dict[str, str | int]:
        original_name = Path(file.filename or "unknown.bin").name or "unknown.bin"
        suffix = Path(original_name).suffix.lower()
        if allowed_suffixes is not None:
            normalized_suffixes = {item.lower() for item in allowed_suffixes}
            if suffix not in normalized_suffixes:
                allowed_text = ", ".join(sorted(normalized_suffixes))
                raise HTTPException(status_code=400, detail=f"仅支持上传以下类型的文件：{allowed_text}")

        file_id = uuid4().hex
        stored_name = f"{file_id}{suffix}" if suffix else file_id
        target = self.upload_dir / stored_name
        limit = max_size_bytes if max_size_bytes is not None else self.default_max_upload_bytes()
        size = 0

        try:
            with target.open("wb") as handle:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if limit > 0 and size > limit:
                        raise HTTPException(status_code=400, detail=f"上传文件过大，超过限制 {limit} 字节。")
                    handle.write(chunk)
        except Exception:
            target.unlink(missing_ok=True)
            raise
        finally:
            await file.close()

        if size <= 0:
            target.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="上传文件为空。")

        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        record = {
            "file_id": file_id,
            "original_name": original_name,
            "stored_name": stored_name,
            "file_path": str(target.resolve()),
            "size": size,
            "created_at": created_at,
        }
        db_service.save_file(record)
        return record

    def default_max_upload_bytes(self) -> int:
        return self.env_int("APP_MAX_UPLOAD_BYTES", 104857600)

    def env_int(self, name: str, default: int) -> int:
        raw_value = os.getenv(name, "").strip()
        if not raw_value:
            return default
        try:
            return int(raw_value)
        except ValueError:
            return default


file_service = FileService()
