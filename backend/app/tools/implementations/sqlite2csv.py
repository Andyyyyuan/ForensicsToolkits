import csv
import sqlite3
import zipfile
from pathlib import Path
from uuid import uuid4

from app.core.paths import get_report_dir
from app.tools.base import BaseTool
from app.tools.registry import tool_registry


class SQLite2CSVTool(BaseTool):
    tool_id = "sqlite2csv"
    name = "SQLite 导出"
    description = "读取 SQLite 数据库，按表导出为 CSV，并生成压缩包下载。"
    input_types = [".db", ".sqlite", ".sqlite3", ".db3"]

    async def run(self, file_path: str | Path, params: dict | None = None) -> dict:
        path = Path(file_path)
        self._validate_sqlite(path)

        export_id = uuid4().hex
        base_name = path.stem.replace(".", "_")
        output_root = get_report_dir() / "sqlite2csv" / export_id
        csv_root = output_root / base_name
        csv_root.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(path) as connection:
            connection.row_factory = sqlite3.Row
            tables = self._get_tables(connection)
            if not tables:
                raise ValueError("数据库中没有可导出的数据表。")

            exported_tables: list[dict] = []
            for table_name in tables:
                csv_path, row_count, columns = self._export_table(connection, table_name, csv_root)
                exported_tables.append(
                    {
                        "table_name": table_name,
                        "row_count": row_count,
                        "columns": columns,
                        "csv_name": csv_path.name,
                        "csv_url": self._to_storage_url(csv_path),
                    }
                )

        zip_path = output_root / f"{base_name}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for csv_file in csv_root.glob("*.csv"):
                archive.write(csv_file, arcname=f"{base_name}/{csv_file.name}")

        return {
            "database_name": path.name,
            "table_count": len(exported_tables),
            "tables": exported_tables,
            "zip_name": zip_path.name,
            "zip_url": self._to_storage_url(zip_path),
        }

    def _validate_sqlite(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            raise ValueError("数据库文件不存在。")
        with path.open("rb") as handle:
            header = handle.read(16)
        if header != b"SQLite format 3\x00":
            raise ValueError("上传文件不是有效的 SQLite 数据库。")

    def _get_tables(self, connection: sqlite3.Connection) -> list[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return [str(row[0]) for row in rows]

    def _export_table(
        self,
        connection: sqlite3.Connection,
        table_name: str,
        csv_root: Path,
    ) -> tuple[Path, int, list[str]]:
        cursor = connection.execute(f'SELECT * FROM "{table_name}"')
        columns = [item[0] for item in cursor.description] if cursor.description else []
        csv_path = csv_root / f"{table_name}.csv"

        row_count = 0
        with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            if columns:
                writer.writerow(columns)
            for row in cursor:
                writer.writerow(list(row))
                row_count += 1

        return csv_path, row_count, columns

    def _to_storage_url(self, path: Path) -> str:
        report_root = get_report_dir()
        if report_root not in path.parents and path != report_root:
            raise ValueError("无法定位报告目录。")
        relative = path.relative_to(report_root).as_posix()
        return f"/storage/reports/{relative}"


def register_sqlite2csv_tool() -> None:
    if not tool_registry.has_tool("sqlite2csv"):
        tool_registry.register(SQLite2CSVTool())
