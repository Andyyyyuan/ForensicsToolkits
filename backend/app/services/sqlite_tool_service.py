import sqlite3
from pathlib import Path

from app.core.paths import get_report_dir


class SqliteToolService:
    def validate_database(self, path: str | Path) -> Path:
        database_path = Path(path)
        if not database_path.exists() or not database_path.is_file():
            raise ValueError("数据库文件不存在。")
        with database_path.open("rb") as handle:
            header = handle.read(16)
        if header != b"SQLite format 3\x00":
            raise ValueError("上传文件不是有效的 SQLite 数据库。")
        return database_path

    def list_tables(self, connection: sqlite3.Connection) -> list[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return [str(row[0]) for row in rows]

    def to_storage_url(self, path: str | Path) -> str:
        report_root = get_report_dir()
        target_path = Path(path)
        if report_root not in target_path.parents and target_path != report_root:
            raise ValueError("无法定位报告目录。")
        relative = target_path.relative_to(report_root).as_posix()
        return f"/storage/reports/{relative}"


sqlite_tool_service = SqliteToolService()
