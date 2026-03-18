import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.paths import get_db_path


class DBService:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else get_db_path()

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS uploaded_files (
                    file_id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    stored_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS parsed_logs (
                    file_id TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (file_id) REFERENCES uploaded_files(file_id)
                )
                """
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def save_file(self, file_record: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO uploaded_files (file_id, original_name, stored_name, file_path, size, created_at)
                VALUES (:file_id, :original_name, :stored_name, :file_path, :size, :created_at)
                """,
                file_record,
            )
            connection.commit()

    def get_file(self, file_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM uploaded_files WHERE file_id = ?",
                (file_id,),
            ).fetchone()
        return dict(row) if row else None

    def save_parsed_result(self, file_id: str, result: dict[str, Any]) -> None:
        payload = {
            "file_id": file_id,
            "result_json": json.dumps(result, ensure_ascii=False),
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO parsed_logs (file_id, result_json, updated_at)
                VALUES (:file_id, :result_json, :updated_at)
                ON CONFLICT(file_id) DO UPDATE SET
                    result_json = excluded.result_json,
                    updated_at = excluded.updated_at
                """,
                payload,
            )
            connection.commit()

    def get_parsed_result(self, file_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM parsed_logs WHERE file_id = ?",
                (file_id,),
            ).fetchone()
        if not row:
            return None
        return json.loads(row["result_json"])


db_service = DBService()
