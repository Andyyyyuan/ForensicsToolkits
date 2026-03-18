from datetime import datetime, timedelta, timezone
from typing import Callable
from zoneinfo import ZoneInfo, available_timezones

from app.tools.base import BaseTool
from app.tools.registry import tool_registry

TIMESTAMP_METHODS = {
    "auto": "自动识别",
    "unix": "UNIX",
    "chrome_webkit": "Chrome/WebKit",
    "ios": "iOS",
    "dotnet_ticks": ".NET Ticks",
    "windows_filetime": "Windows FileTime",
    "apple_absolute_time": "Apple Absolute Time",
}


class TimestampParserTool(BaseTool):
    tool_id = "timestamp_parser"
    name = "时间戳转换"
    description = "将常见取证时间戳转换为指定时区的标准时间。"
    input_types = []
    requires_file = False

    async def run(self, file_path: str, params: dict | None = None) -> dict:
        options = params or {}
        raw_timestamp = str(options.get("timestamp", "")).strip()
        method = str(options.get("timestamp_type", "auto")).strip()
        origin_timezone = str(options.get("origin_timezone", "UTC")).strip() or "UTC"
        target_timezone = str(options.get("target_timezone", "Asia/Shanghai")).strip() or "Asia/Shanghai"

        if not raw_timestamp:
            raise ValueError("timestamp 不能为空。")
        if method not in TIMESTAMP_METHODS:
            raise ValueError("不支持的时间戳类型。")
        self._validate_timezone(origin_timezone)
        self._validate_timezone(target_timezone)

        value = self._parse_numeric(raw_timestamp)
        detected_method = self._detect_timestamp_type(value) if method == "auto" else method
        converted = self._convert_timestamp(value, detected_method, origin_timezone, target_timezone)
        detected_label = self._timestamp_label(detected_method, value)

        return {
            "timestamp": raw_timestamp,
            "timestamp_type": detected_method,
            "timestamp_type_label": detected_label,
            "origin_timezone": origin_timezone,
            "target_timezone": target_timezone,
            "converted_time": converted,
            "supported_timezones": [
                "UTC",
                "Asia/Shanghai",
                "Asia/Tokyo",
                "America/New_York",
                "Europe/London",
            ],
        }

    def _validate_timezone(self, timezone_name: str) -> None:
        if timezone_name not in available_timezones():
            raise ValueError(f"不支持的时区：{timezone_name}")

    def _parse_numeric(self, raw_timestamp: str) -> int | float:
        try:
            if "." in raw_timestamp:
                return float(raw_timestamp)
            return int(raw_timestamp)
        except ValueError as exc:
            raise ValueError("时间戳必须是数字。") from exc

    def _convert_timestamp(
        self,
        timestamp: int | float,
        method: str,
        origin_timezone: str,
        target_timezone: str,
    ) -> str:
        if method == "unix":
            return self._default_timestamp_to_datetime(timestamp, origin_timezone, target_timezone)
        if method == "chrome_webkit":
            return self._chrome_timestamp_to_datetime(timestamp, origin_timezone, target_timezone)
        if method == "ios":
            return self._ios_timestamp_to_datetime(timestamp, origin_timezone, target_timezone)
        if method == "dotnet_ticks":
            return self._dotnet_ticks_to_datetime(timestamp, origin_timezone, target_timezone)
        if method == "windows_filetime":
            return self._windows_file_time_to_datetime(timestamp, origin_timezone, target_timezone)
        if method == "apple_absolute_time":
            return self._apple_timestamp_to_datetime(timestamp, origin_timezone, target_timezone)
        raise ValueError("不支持的时间戳类型。")

    def _detect_timestamp_type(self, timestamp: int | float) -> str:
        integer_part = str(int(abs(float(timestamp))))
        length = len(integer_part)

        if length in {10, 13, 16, 19}:
            return "unix"
        if length >= 18:
            if int(float(timestamp)) >= 600_000_000_000_000_000:
                return "dotnet_ticks"
            return "windows_filetime"
        if length >= 15:
            return "chrome_webkit"

        unix_year = self._safe_year(lambda: self._default_timestamp_to_datetime(timestamp, "UTC", "UTC"))
        ios_year = self._safe_year(lambda: self._ios_timestamp_to_datetime(timestamp, "UTC", "UTC"))
        apple_year = self._safe_year(lambda: self._apple_timestamp_to_datetime(timestamp, "UTC", "UTC"))

        if unix_year and 2000 <= unix_year <= 2100:
            return "unix"
        if ios_year and 2001 <= ios_year <= 2100:
            return "ios"
        if apple_year and 2001 <= apple_year <= 2100:
            return "apple_absolute_time"
        return "unix"

    def _timestamp_label(self, method: str, timestamp: int | float) -> str:
        if method != "unix":
            return TIMESTAMP_METHODS[method]
        precision = self._detect_unix_precision(timestamp)
        return f"UNIX ({precision})"

    def _detect_unix_precision(self, timestamp: int | float) -> str:
        as_text = str(int(abs(float(timestamp)))) if float(timestamp).is_integer() else str(abs(float(timestamp)))
        length = len(as_text.split(".")[0])
        if length == 13:
            return "毫秒"
        if length == 16:
            return "微秒"
        if length == 19:
            return "纳秒"
        return "秒"

    def _safe_year(self, formatter: Callable[[], str]) -> int | None:
        try:
            formatted = formatter()
            return int(formatted[:4])
        except Exception:  # noqa: BLE001
            return None

    def _format_datetime(self, dt: datetime, origin_timezone: str, target_timezone: str) -> str:
        localized = dt.replace(tzinfo=ZoneInfo(origin_timezone))
        target_dt = localized.astimezone(ZoneInfo(target_timezone))
        return target_dt.strftime("%Y-%m-%d %H:%M:%S")

    def _ios_timestamp_to_datetime(self, timestamp: int | float, origin_timezone: str, target_timezone: str) -> str:
        base_time = datetime(2001, 1, 1)
        converted_time = base_time + timedelta(seconds=float(timestamp))
        return self._format_datetime(converted_time, origin_timezone, target_timezone)

    def _default_timestamp_to_datetime(self, timestamp: int | float, origin_timezone: str, target_timezone: str) -> str:
        as_text = str(int(timestamp)) if isinstance(timestamp, int) or float(timestamp).is_integer() else str(timestamp)
        length = len(as_text.split(".")[0])
        if length == 13:
            dt = datetime.fromtimestamp(float(timestamp) / 1000, tz=timezone.utc).replace(tzinfo=None)
        elif length == 16:
            dt = datetime.fromtimestamp(float(timestamp) / 1_000_000, tz=timezone.utc).replace(tzinfo=None)
        elif length == 19:
            dt = datetime.fromtimestamp(float(timestamp) / 1_000_000_000, tz=timezone.utc).replace(tzinfo=None)
        else:
            dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc).replace(tzinfo=None)
        return self._format_datetime(dt, origin_timezone, target_timezone)

    def _chrome_timestamp_to_datetime(self, timestamp: int | float, origin_timezone: str, target_timezone: str) -> str:
        base_time = datetime(1601, 1, 1)
        converted_time = base_time + timedelta(microseconds=float(timestamp))
        return self._format_datetime(converted_time, origin_timezone, target_timezone)

    def _windows_file_time_to_datetime(
        self, timestamp: int | float, origin_timezone: str, target_timezone: str
    ) -> str:
        base_time = datetime(1601, 1, 1)
        converted_time = base_time + timedelta(microseconds=float(timestamp) / 10)
        return self._format_datetime(converted_time, origin_timezone, target_timezone)

    def _dotnet_ticks_to_datetime(self, timestamp: int | float, origin_timezone: str, target_timezone: str) -> str:
        value = int(timestamp) - 621355968000000000
        return self._default_timestamp_to_datetime(value // 10000, origin_timezone, target_timezone)

    def _apple_timestamp_to_datetime(self, timestamp: int | float, origin_timezone: str, target_timezone: str) -> str:
        converted = int(float(timestamp)) + 978307200
        dt = datetime.fromtimestamp(converted, tz=timezone.utc).replace(tzinfo=None)
        return self._format_datetime(dt, origin_timezone, target_timezone)


def register_timestamp_parser_tool() -> None:
    if not tool_registry.has_tool("timestamp_parser"):
        tool_registry.register(TimestampParserTool())
