import os
from dataclasses import dataclass

from app.services.cyberchef_service import cyberchef_service


class ToolDisabledError(Exception):
    def __init__(self, tool_id: str, title: str, message: str) -> None:
        super().__init__(message)
        self.tool_id = tool_id
        self.title = title
        self.message = message


@dataclass(slots=True)
class ToolAvailability:
    enabled: bool
    disabled_title: str | None = None
    disabled_message: str | None = None


class ToolConfigService:
    def _env_key_prefix(self, tool_id: str) -> str:
        normalized = tool_id.upper().replace("-", "_")
        return f"TOOL_{normalized}"

    def _default_enabled(self, tool_id: str) -> bool:
        if tool_id == "encoding_converter":
            return cyberchef_service.is_available()
        return True

    def _env_flag(self, name: str, default: bool) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    def get_availability(self, tool_id: str) -> ToolAvailability:
        prefix = self._env_key_prefix(tool_id)
        default_enabled = self._default_enabled(tool_id)
        enabled = self._env_flag(f"{prefix}_ENABLED", default=default_enabled)
        disabled_title = os.getenv(f"{prefix}_DISABLED_TITLE", "").strip() or "功能暂未开放"
        disabled_message = (
            os.getenv(f"{prefix}_DISABLED_MESSAGE", "").strip()
            or "当前部署环境未启用该功能，请联系管理员或切换到允许该功能的本地部署环境。"
        )

        if tool_id == "encoding_converter" and not enabled and not default_enabled:
            disabled_title = os.getenv(f"{prefix}_DISABLED_TITLE", "").strip() or "CyberChef 未就绪"
            disabled_message = (
                os.getenv(f"{prefix}_DISABLED_MESSAGE", "").strip()
                or f"未发现可用的 CyberChef 目录：{cyberchef_service.get_directory()}。"
            )

        if enabled:
            return ToolAvailability(enabled=True)

        return ToolAvailability(
            enabled=False,
            disabled_title=disabled_title,
            disabled_message=disabled_message,
        )

    def ensure_enabled(self, tool_id: str) -> None:
        availability = self.get_availability(tool_id)
        if availability.enabled:
            return
        raise ToolDisabledError(
            tool_id=tool_id,
            title=availability.disabled_title or "功能暂未开放",
            message=availability.disabled_message
            or "当前部署环境未启用该功能，请联系管理员或切换到允许该功能的本地部署环境。",
        )


tool_config_service = ToolConfigService()
