import csv
import sqlite3
from pathlib import Path
from uuid import uuid4

from app.core.paths import get_report_dir
from app.schemas.tools import (
    SqliteBrowserResponse,
    SqliteExportRequest,
    SqliteExportResponse,
    SqlitePreviewFilterRequest,
    SqlitePreviewRequest,
    SqlitePreviewResponse,
    SqliteTableColumnResponse,
    SqliteTableInfoResponse,
)


class SQLiteBrowserService:
    def inspect_database(self, file_path: str | Path, file_id: str, database_name: str) -> SqliteBrowserResponse:
        path = Path(file_path)
        self._validate_sqlite(path)

        with sqlite3.connect(path) as connection:
            connection.row_factory = sqlite3.Row
            tables = [self._build_table_info(connection, table_name) for table_name in self._get_tables(connection)]

        return SqliteBrowserResponse(
            file_id=file_id,
            database_name=database_name,
            tables=tables,
        )

    def preview_table(self, file_path: str | Path, payload: SqlitePreviewRequest) -> SqlitePreviewResponse:
        path = Path(file_path)
        self._validate_sqlite(path)

        with sqlite3.connect(path) as connection:
            connection.row_factory = sqlite3.Row
            table_name = self._validate_table(connection, payload.table_name)
            available_columns = self._get_table_columns(connection, table_name)
            selected_columns = self._normalize_selected_columns(payload.selected_columns, available_columns)
            where_clause, parameters = self._build_where_clause(payload.filters, available_columns)

            sql_columns = ", ".join(self._quote_identifier(column) for column in selected_columns)
            preview_sql = (
                f"SELECT {sql_columns} FROM {self._quote_identifier(table_name)} "
                f"{where_clause} LIMIT ? OFFSET ?"
            )
            rows = [
                dict(row)
                for row in connection.execute(preview_sql, [*parameters, payload.limit, payload.offset]).fetchall()
            ]

            count_sql = f"SELECT COUNT(*) AS total_rows FROM {self._quote_identifier(table_name)} {where_clause}"
            total_rows = int(connection.execute(count_sql, parameters).fetchone()["total_rows"])

        return SqlitePreviewResponse(
            table_name=table_name,
            selected_columns=selected_columns,
            available_columns=available_columns,
            rows=rows,
            total_rows=total_rows,
            returned_rows=len(rows),
        )

    def export_table(self, file_path: str | Path, payload: SqliteExportRequest) -> SqliteExportResponse:
        path = Path(file_path)
        self._validate_sqlite(path)
        export_id = uuid4().hex
        output_dir = get_report_dir() / "sqlite_browser" / export_id
        output_dir.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(path) as connection:
            connection.row_factory = sqlite3.Row
            table_name = self._validate_table(connection, payload.table_name)
            available_columns = self._get_table_columns(connection, table_name)
            selected_columns = self._normalize_selected_columns(payload.selected_columns, available_columns)
            where_clause, parameters = self._build_where_clause(payload.filters, available_columns)
            sql_columns = ", ".join(self._quote_identifier(column) for column in selected_columns)
            export_sql = f"SELECT {sql_columns} FROM {self._quote_identifier(table_name)} {where_clause}"
            rows = connection.execute(export_sql, parameters)

            csv_path = output_dir / f"{table_name}.csv"
            delimiter = "\t" if payload.delimiter == "\\t" else payload.delimiter
            row_count = 0
            with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle, delimiter=delimiter)
                if payload.include_header:
                    writer.writerow(selected_columns)
                for row in rows:
                    writer.writerow([row[column] for column in selected_columns])
                    row_count += 1

        return SqliteExportResponse(
            table_name=table_name,
            csv_name=csv_path.name,
            csv_url=self._to_storage_url(csv_path),
            row_count=row_count,
            columns=selected_columns,
        )

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

    def _build_table_info(self, connection: sqlite3.Connection, table_name: str) -> SqliteTableInfoResponse:
        columns = self._get_table_columns(connection, table_name)
        row_count = int(
            connection.execute(
                f"SELECT COUNT(*) AS row_count FROM {self._quote_identifier(table_name)}"
            ).fetchone()["row_count"]
        )
        schema_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name = ?",
            (table_name,),
        ).fetchone()
        return SqliteTableInfoResponse(
            table_name=table_name,
            row_count=row_count,
            columns=columns,
            schema_sql=str(schema_row["sql"]) if schema_row and schema_row["sql"] else None,
        )

    def _get_table_columns(self, connection: sqlite3.Connection, table_name: str) -> list[SqliteTableColumnResponse]:
        rows = connection.execute(f"PRAGMA table_info({self._quote_identifier(table_name)})").fetchall()
        columns: list[SqliteTableColumnResponse] = []
        for row in rows:
            columns.append(
                SqliteTableColumnResponse(
                    name=str(row["name"]),
                    type=str(row["type"] or ""),
                    not_null=bool(row["notnull"]),
                    default_value=None if row["dflt_value"] is None else str(row["dflt_value"]),
                    is_primary_key=bool(row["pk"]),
                )
            )
        return columns

    def _validate_table(self, connection: sqlite3.Connection, table_name: str) -> str:
        available_tables = set(self._get_tables(connection))
        if table_name not in available_tables:
            raise ValueError(f"数据表不存在：{table_name}")
        return table_name

    def _normalize_selected_columns(
        self,
        selected_columns: list[str],
        available_columns: list[SqliteTableColumnResponse],
    ) -> list[str]:
        available_names = [column.name for column in available_columns]
        if not selected_columns:
            return available_names
        normalized = [column for column in selected_columns if column in available_names]
        if not normalized:
            raise ValueError("选定字段无效，请重新选择。")
        return normalized

    def _build_where_clause(
        self,
        filters: list[SqlitePreviewFilterRequest],
        available_columns: list[SqliteTableColumnResponse],
    ) -> tuple[str, list[str]]:
        available_names = {column.name for column in available_columns}
        conditions: list[str] = []
        parameters: list[str] = []

        for item in filters:
            if item.column not in available_names:
                raise ValueError(f"筛选字段不存在：{item.column}")

            quoted_column = self._quote_identifier(item.column)
            operator = item.operator
            value = item.value or ""

            if operator == "contains":
                conditions.append(f"CAST({quoted_column} AS TEXT) LIKE ?")
                parameters.append(f"%{value}%")
            elif operator == "equals":
                conditions.append(f"CAST({quoted_column} AS TEXT) = ?")
                parameters.append(value)
            elif operator == "starts_with":
                conditions.append(f"CAST({quoted_column} AS TEXT) LIKE ?")
                parameters.append(f"{value}%")
            elif operator == "ends_with":
                conditions.append(f"CAST({quoted_column} AS TEXT) LIKE ?")
                parameters.append(f"%{value}")
            elif operator == "gt":
                conditions.append(f"{quoted_column} > ?")
                parameters.append(value)
            elif operator == "gte":
                conditions.append(f"{quoted_column} >= ?")
                parameters.append(value)
            elif operator == "lt":
                conditions.append(f"{quoted_column} < ?")
                parameters.append(value)
            elif operator == "lte":
                conditions.append(f"{quoted_column} <= ?")
                parameters.append(value)
            elif operator == "is_null":
                conditions.append(f"{quoted_column} IS NULL")
            elif operator == "not_null":
                conditions.append(f"{quoted_column} IS NOT NULL")

        if not conditions:
            return "", []
        return f"WHERE {' AND '.join(conditions)}", parameters

    def _quote_identifier(self, value: str) -> str:
        return f'"{value.replace(chr(34), chr(34) * 2)}"'

    def _to_storage_url(self, path: Path) -> str:
        report_root = get_report_dir()
        if report_root not in path.parents and path != report_root:
            raise ValueError("无法定位报告目录。")
        relative = path.relative_to(report_root).as_posix()
        return f"/storage/reports/{relative}"


sqlite_browser_service = SQLiteBrowserService()
