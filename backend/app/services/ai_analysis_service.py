import base64
import binascii
import html
import json
import os
import re
from urllib.parse import unquote
from pathlib import Path
from typing import Any, AsyncIterator, Callable

import httpx

from app.schemas.log_parser import AIAnalysisResult, FindingItem, ParseStrategy, ParsedLogResponse
from app.services.db_service import db_service
from app.services.hashcat_service import hashcat_service

DEFAULT_PARSE_STRATEGY = ParseStrategy(
    source="fallback",
    log_type="generic-text-log",
    overview="这是一份通用文本日志，主要记录运行状态、事件过程以及可能的异常或告警信息。",
    error_keywords=["error", "exception", "fatal", "traceback", "failed", "denied", "unauthorized"],
    warning_keywords=["warning", "warn", "deprecated", "retry"],
    info_keywords=["info", "notice", "start", "started", "success", "ready"],
    fragment_keywords=["error", "exception", "fatal", "traceback", "failed", "timeout", "denied", "unauthorized"],
    notes=[
        "未获取到 AI 解析策略时，系统会使用本地通用日志策略。",
        "通用策略适合大多数纯文本日志，但不保证覆盖业务自定义字段。",
    ],
)

SUPPORTED_TIMEZONES = ["UTC", "Asia/Shanghai", "Asia/Tokyo", "America/New_York", "Europe/London"]
SUPPORTED_TIMESTAMP_TYPES = [
    "auto",
    "unix",
    "chrome_webkit",
    "ios",
    "dotnet_ticks",
    "windows_filetime",
    "apple_absolute_time",
]
SUPPORTED_ENCODING_NAMES = [
    "UTF-8",
    "UTF-16LE",
    "UTF-16BE",
    "GBK",
    "GB18030",
    "Base64",
    "Base32",
    "Hex",
    "URL",
    "Unicode Escape",
    "HTML Entity",
    "JSON Escape",
]
SYSTEM_RESPONSE_STYLE = (
    "必须用中文回答。"
    "不要使用生硬的通用称呼。"
    "如需称呼，请使用“同学你好”。"
    "结论要和证据对应，证据不足时明确说明不足点。"
    "表达要简洁、专业、克制、可执行，不要写空泛套话。"
)


class AIAnalysisService:
    def __init__(self) -> None:
        self.api_base_url = ""
        self.api_key = ""
        self.chat_model = ""
        self.reasoner_model = ""
        self._refresh_config()

    def _refresh_config(self) -> None:
        self.api_base_url = os.getenv("AI_API_BASE_URL", "").rstrip("/")
        self.api_key = os.getenv("AI_API_KEY", "")
        default_model = os.getenv("AI_MODEL", "")
        self.chat_model = os.getenv("AI_CHAT_MODEL", "").strip() or default_model
        self.reasoner_model = os.getenv("AI_REASONER_MODEL", "").strip() or self.chat_model

    def is_configured(self) -> bool:
        self._refresh_config()
        return bool(self.api_base_url and self.api_key and self.chat_model and self.reasoner_model)

    def get_model_name(self, mode: str) -> str:
        self._refresh_config()
        return self.reasoner_model if mode == "reasoner" else self.chat_model

    async def suggest_parse_strategy(self, file_name: str, sample_lines: list[str]) -> ParseStrategy:
        self._refresh_config()
        if not self.is_configured():
            return DEFAULT_PARSE_STRATEGY

        system_prompt = (
            "你是一名电子取证日志解析助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            "同学你好，下面会提供日志文件名和前若干行样本。"
            "你只能依据样本建议基础解析策略，不得编造样本中不存在的结构。"
            "只输出 JSON，字段必须包含："
            "log_type、overview、error_keywords、warning_keywords、info_keywords、fragment_keywords、notes。"
            "overview 只概述日志类型和主要内容，不要写缺少 error 或 warning 的元描述。"
            "不要返回 markdown。"
        )
        user_payload = {
            "file_name": file_name,
            "sample_lines": sample_lines,
            "constraints": [
                "overview 用一到两句话概括日志类型和主要内容。",
                "关键字尽量简短，适合直接用于字符串匹配。",
                "如样本不足以判断，可返回通用关键字，并在 notes 中明确说明证据不足。",
            ],
        }

        try:
            content, _ = await self._request_json_completion(
                model=self.chat_model,
                system_prompt=system_prompt,
                user_payload=user_payload,
            )
            strategy_data = self._normalize_strategy_payload(self._parse_json_content(content))
            return ParseStrategy(source="ai", **strategy_data)
        except Exception as exc:  # noqa: BLE001
            fallback = DEFAULT_PARSE_STRATEGY.model_copy(deep=True)
            fallback.notes.append(f"AI 解析策略获取失败，已回退到本地规则。原因：{exc}")
            return fallback

    async def analyze_with_meta(
        self,
        parsed_result: ParsedLogResponse,
        question: str,
        mode: str = "reasoner",
    ) -> tuple[str, AIAnalysisResult, str]:
        self._refresh_config()
        if self.is_configured():
            try:
                result, reasoning = await self._analyze_with_remote_model(parsed_result, question, mode)
                return "ai", result, reasoning
            except Exception as exc:  # noqa: BLE001
                fallback = self._analyze_with_local_fallback(parsed_result, question)
                fallback.recommendations.insert(0, f"外部 AI 调用失败，已切换为本地规则分析。原因：{exc}")
                return "fallback", fallback, ""
        return "fallback", self._analyze_with_local_fallback(parsed_result, question), ""

    async def assist_timestamp(self, raw_input: str, mode: str = "chat") -> dict[str, Any]:
        result, _, _ = await self.assist_timestamp_with_meta(raw_input, mode)
        return result

    async def assist_timestamp_with_meta(self, raw_input: str, mode: str = "chat") -> tuple[dict[str, Any], str, str]:
        self._refresh_config()
        if self.is_configured():
            try:
                result, reasoning = await self._assist_timestamp_with_model(raw_input, mode)
                return result, "ai", reasoning
            except Exception as exc:  # noqa: BLE001
                result = self._assist_timestamp_fallback(raw_input)
                result["warnings"].append(f"AI 辅助失败，已回退为本地识别。原因：{exc}")
                return result, "fallback", ""
        return self._assist_timestamp_fallback(raw_input), "fallback", ""

    async def assist_hashcat(
        self,
        raw_input: str,
        mode: str = "chat",
        *,
        file_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result, _, _ = await self.assist_hashcat_with_meta(raw_input, mode, file_id=file_id, context=context)
        return result

    async def assist_hashcat_with_meta(
        self,
        raw_input: str,
        mode: str = "chat",
        *,
        file_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str, str]:
        self._refresh_config()
        hashcat_payload = self._build_hashcat_ai_payload(raw_input, file_id=file_id, context=context)
        hash_file_context = hashcat_payload["hashcat_context"].get("hash_file")
        if self.is_configured():
            try:
                result, reasoning = await self._assist_hashcat_with_model(raw_input, mode, hashcat_payload=hashcat_payload)
                return result, "ai", reasoning
            except Exception as exc:  # noqa: BLE001
                result = self._assist_hashcat_fallback(raw_input, context=context, file_context=hash_file_context)
                result["warnings"].append(f"AI 辅助失败，已回退为本地识别。原因：{exc}")
                return result, "fallback", ""
        return self._assist_hashcat_fallback(raw_input, context=context, file_context=hash_file_context), "fallback", ""

    async def assist_encoding(self, raw_input: str, mode: str = "chat") -> dict[str, Any]:
        result, _, _ = await self.assist_encoding_with_meta(raw_input, mode)
        return result

    async def assist_encoding_with_meta(self, raw_input: str, mode: str = "chat") -> tuple[dict[str, Any], str, str]:
        self._refresh_config()
        if self.is_configured():
            try:
                result, reasoning = await self._assist_encoding_with_model(raw_input, mode)
                return result, "ai", reasoning
            except Exception as exc:  # noqa: BLE001
                result = self._assist_encoding_fallback(raw_input)
                result["warnings"].append(f"AI 辅助失败，已回退为本地识别。原因：{exc}")
                return result, "fallback", ""
        return self._assist_encoding_fallback(raw_input), "fallback", ""

    async def assist_hash_result_with_meta(
        self,
        raw_input: str,
        context: dict[str, Any] | None = None,
        mode: str = "chat",
    ) -> tuple[dict[str, Any], str, str]:
        self._refresh_config()
        normalized_context = context or {}
        if self.is_configured():
            try:
                result, reasoning = await self._assist_hash_result_with_model(raw_input, normalized_context, mode)
                return result, "ai", reasoning
            except Exception as exc:  # noqa: BLE001
                result = self._assist_hash_result_fallback(raw_input, normalized_context)
                result["warnings"].append(f"AI 辅助失败，已回退为本地分析。原因：{exc}")
                return result, "fallback", ""
        return self._assist_hash_result_fallback(raw_input, normalized_context), "fallback", ""

    async def assist_sqlite_result_with_meta(
        self,
        raw_input: str,
        context: dict[str, Any] | None = None,
        mode: str = "chat",
    ) -> tuple[dict[str, Any], str, str]:
        self._refresh_config()
        normalized_context = context or {}
        if self.is_configured():
            try:
                result, reasoning = await self._assist_sqlite_result_with_model(raw_input, normalized_context, mode)
                return result, "ai", reasoning
            except Exception as exc:  # noqa: BLE001
                result = self._assist_sqlite_result_fallback(raw_input, normalized_context)
                result["warnings"].append(f"AI 辅助失败，已回退为本地分析。原因：{exc}")
                return result, "fallback", ""
        return self._assist_sqlite_result_fallback(raw_input, normalized_context), "fallback", ""

    async def stream_log_analysis(
        self,
        parsed_result: ParsedLogResponse,
        question: str,
        mode: str = "reasoner",
    ) -> AsyncIterator[dict[str, Any]]:
        async for event in self._stream_tool_result(
            tool_id="log_parser",
            mode=mode,
            normalizer=self._normalize_analysis_payload,
            fallback_factory=lambda error: {
                "source": "fallback",
                "result": self._analyze_with_local_fallback(parsed_result, question).model_dump(),
                "warning": f"外部 AI 调用失败，已切换为本地规则分析。原因：{error}",
            },
            system_prompt=self._log_analysis_prompt(),
            user_payload=self._build_evidence_bundle(parsed_result, question),
        ):
            yield event

    async def stream_timestamp_assist(self, raw_input: str, mode: str = "reasoner") -> AsyncIterator[dict[str, Any]]:
        async for event in self._stream_tool_result(
            tool_id="timestamp_parser",
            mode=mode,
            normalizer=self._normalize_timestamp_assist_payload,
            fallback_factory=lambda error: self._fallback_stream_payload(self._assist_timestamp_fallback(raw_input), error),
            system_prompt=self._timestamp_assist_prompt(),
            user_payload={"user_input": raw_input, "output_requirement": "输出必须是 JSON，explanation 和 warnings 必须使用中文。"},
        ):
            yield event

    async def stream_hashcat_assist(
        self,
        raw_input: str,
        mode: str = "reasoner",
        *,
        file_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        hashcat_payload = self._build_hashcat_ai_payload(raw_input, file_id=file_id, context=context)
        hash_file_context = hashcat_payload["hashcat_context"].get("hash_file")
        async for event in self._stream_tool_result(
            tool_id="hashcat_gui",
            mode=mode,
            normalizer=self._normalize_hashcat_assist_payload,
            fallback_factory=lambda error: self._fallback_stream_payload(
                self._assist_hashcat_fallback(raw_input, context=context, file_context=hash_file_context),
                error,
            ),
            system_prompt=self._hashcat_assist_prompt(),
            user_payload=hashcat_payload,
        ):
            yield event

    async def stream_encoding_assist(self, raw_input: str, mode: str = "reasoner") -> AsyncIterator[dict[str, Any]]:
        async for event in self._stream_tool_result(
            tool_id="encoding_converter",
            mode=mode,
            normalizer=lambda payload: self._normalize_encoding_assist_payload(payload, raw_input=raw_input),
            fallback_factory=lambda error: self._fallback_stream_payload(self._assist_encoding_fallback(raw_input), error),
            system_prompt=self._encoding_assist_prompt(),
            user_payload=self._build_encoding_ai_payload(raw_input),
        ):
            yield event

    async def stream_hash_result_assist(
        self,
        raw_input: str,
        context: dict[str, Any] | None = None,
        mode: str = "reasoner",
    ) -> AsyncIterator[dict[str, Any]]:
        normalized_context = context or {}
        async for event in self._stream_tool_result(
            tool_id="hash_tool",
            mode=mode,
            normalizer=self._normalize_hash_result_assist_payload,
            fallback_factory=lambda error: self._fallback_stream_payload(
                self._assist_hash_result_fallback(raw_input, normalized_context),
                error,
            ),
            system_prompt=self._hash_result_assist_prompt(),
            user_payload={
                "user_input": raw_input,
                "hash_context": normalized_context,
                "output_requirement": "输出必须是 JSON，所有说明必须使用中文。",
            },
        ):
            yield event

    async def stream_sqlite_result_assist(
        self,
        raw_input: str,
        context: dict[str, Any] | None = None,
        mode: str = "reasoner",
    ) -> AsyncIterator[dict[str, Any]]:
        normalized_context = context or {}
        async for event in self._stream_tool_result(
            tool_id="sqlite2csv",
            mode=mode,
            normalizer=self._normalize_sqlite_assist_payload,
            fallback_factory=lambda error: self._fallback_stream_payload(
                self._assist_sqlite_result_fallback(raw_input, normalized_context),
                error,
            ),
            system_prompt=self._sqlite_assist_prompt(),
            user_payload={
                "user_input": raw_input,
                "sqlite_context": normalized_context,
                "output_requirement": "输出必须是 JSON，所有说明必须使用中文。",
            },
        ):
            yield event

    def _log_analysis_prompt(self) -> str:
        return (
            "你是一名电子取证日志研判助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            "同学你好，请只依据提供的结构化基础解析结果、关键片段和提问进行判断。"
            "禁止编造不存在的事实；证据不足时必须明确说明。"
            "严格输出 JSON，字段必须包含：summary、risk_level、findings、timeline_summary、recommendations。"
            "findings 中的每条结论都必须能对应到输入里的证据。"
        )

    def _timestamp_assist_prompt(self) -> str:
        return (
            "你是一名电子取证时间戳识别助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            "同学你好，请从输入的杂乱文本中提取最可能的时间戳值和类型，并给出建议。"
            "只输出 JSON，字段必须包含：timestamp、timestamp_type、origin_timezone、target_timezone、explanation、confidence、warnings。"
            f"timestamp_type 只能从以下值中选择：{', '.join(SUPPORTED_TIMESTAMP_TYPES)}。"
            f"origin_timezone 和 target_timezone 只能从以下值中选择：{', '.join(SUPPORTED_TIMEZONES)}。"
            "优先依据数值长度、上下文关键字和时区线索判断，不要凭空假设来源系统。"
            "如果证据不足，仍需给出当前最可能的选项，并在 warnings 中说明不确定性。"
        )

    def _hashcat_assist_prompt(self) -> str:
        return (
            "你是一名 Hashcat GUI 配置助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            "同学你好，请结合输入文本、当前表单、运行时默认字典信息以及已上传的 hash 文件样本，识别最可能的 Hash 类型、攻击模式和可直接回填的参数。"
            "只输出 JSON，字段必须包含：hash_mode、attack_mode、wordlist_path、secondary_wordlist_path、mask、session_name、extra_args、explanation、confidence、warnings。"
            "attack_mode 只能是 0、1、3、6、7。"
            "如果用户没有提供额外攻击模式线索，则默认使用 attack_mode=0，并优先沿用用户当前字典或默认 rockyou.txt。"
            "如果用户明确提到两个字典、双字典、组合字典或 combinator，则使用 attack_mode=1，并尽量同时给出 wordlist_path 与 secondary_wordlist_path。"
            "如果用户只提供掩码线索或明确要求纯掩码爆破，则使用 attack_mode=3，并尽量提取 mask，同时把字典字段置空。"
            "如果用户描述的是字典后缀掩码，例如字典后面跟几位数字、末尾补位，则使用 attack_mode=6。"
            "如果用户描述的是掩码前缀字典，例如前面补几位数字再接字典，则使用 attack_mode=7。"
            "如果已上传 hash 文件，请优先结合文件样本判断 hash_mode，并尽量给出可直接回填界面的结果。"
            "不要虚构用户没有提供的文件路径，除默认 rockyou.txt 外不要编造字典。"
            "如果无法完全确认，请给出最可能的方案，并在 warnings 中明确风险。"
        )

    def _encoding_assist_prompt(self) -> str:
        return (
            "你是一名电子取证编码识别助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            "同学你好，请先判断输入更像哪种编码、转义或数据表示形式，再给出 CyberChef 可尝试的配方。"
            "只输出 JSON，字段必须包含：recommended_encoding、candidates、suggested_recipe、cyberchef_recipe、cyberchef_input、explanation、warnings。"
            "candidates 必须是数组，每项字段包含：name、confidence、score、reason。"
            f"name 应优先从以下候选中选择：{', '.join(SUPPORTED_ENCODING_NAMES)}。"
            "score 为 0 到 100 的整数。"
            "必须区分 Base32 与 Base64：Base32 常见字符集主要是 A-Z、2-7 和 =，通常不会出现 +、/；Base64 常见字符集是 A-Z、a-z、0-9、+、/ 和 =。"
            "如果一层解码后仍明显像另一层编码，suggested_recipe 必须按解码顺序输出数组，例如 ['From Base64', 'From Base64'] 或 ['From Base32', 'From Base64']。"
            "只有证据充分时才给出多层判断；若 Base32 与 Base64 存在歧义，必须在 warnings 中说明。"
            "cyberchef_recipe 必须是可直接放入 CyberChef URL recipe 参数的配方字符串。"
            "cyberchef_input 必须保持原始输入，不要自行做 Base64 编码。"
            "不要虚构已经成功解码出的最终明文，只能给出识别判断、分层依据和建议配方。"
        )

    def _hash_result_assist_prompt(self) -> str:
        return (
            "你是一名电子取证哈希分析助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            "同学你好，请结合提问、文件哈希结果和可用元数据，给出可直接执行的取证比对建议。"
            "不要编造未提供的文件来源、恶意结论或情报检索命中结果。"
            "只输出 JSON，字段必须包含：summary、primary_hash、findings、recommendations、warnings、confidence。"
            "findings 必须是字符串数组，每条都要简洁、具体、可执行。"
        )

    def _sqlite_assist_prompt(self) -> str:
        return (
            "你是一名电子取证 SQLite 分析助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            "同学你好，请结合提问、当前数据库表结构、选中表和预览数据，指出优先检查的表、字段和导出方向。"
            "禁止编造数据库中不存在的字段、关系或行内容，只能依据提供的上下文推断。"
            "只输出 JSON，字段必须包含：summary、highlighted_tables、current_table_name、focus_fields、schema_notes、recommendations、warnings。"
            "highlighted_tables 为数组，每项字段必须包含：table_name、priority、reason。priority 只能是 high、medium、low。"
            "优先说明为什么当前表或字段值得关注，而不是泛泛而谈。"
        )

    def _build_encoding_ai_payload(self, raw_input: str) -> dict[str, Any]:
        analysis = self._analyze_encoding_input(raw_input)
        return {
            "user_input": raw_input,
            "encoding_context": analysis["evidence"],
            "suggested_recipe_hint": analysis["suggested_recipe"],
            "output_requirement": (
                "输出必须是 JSON，所有说明必须使用中文。"
                "如果判断为多层编码，suggested_recipe 必须按解码顺序给出多个步骤。"
            ),
        }

    async def _analyze_with_remote_model(
        self,
        parsed_result: ParsedLogResponse,
        question: str,
        mode: str,
    ) -> tuple[AIAnalysisResult, str]:
        content, reasoning = await self._request_json_completion(
            model=self.get_model_name(mode),
            system_prompt=self._log_analysis_prompt(),
            user_payload=self._build_evidence_bundle(parsed_result, question),
        )
        return AIAnalysisResult(**self._normalize_analysis_payload(self._parse_json_content(content))), reasoning

    async def _assist_timestamp_with_model(self, raw_input: str, mode: str) -> tuple[dict[str, Any], str]:
        content, reasoning = await self._request_json_completion(
            model=self.get_model_name(mode),
            system_prompt=self._timestamp_assist_prompt(),
            user_payload={"user_input": raw_input, "output_requirement": "输出必须是 JSON，explanation 和 warnings 必须使用中文。"},
        )
        return self._normalize_timestamp_assist_payload(self._parse_json_content(content)), reasoning

    async def _assist_hashcat_with_model(
        self,
        raw_input: str,
        mode: str,
        *,
        hashcat_payload: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str]:
        content, reasoning = await self._request_json_completion(
            model=self.get_model_name(mode),
            system_prompt=self._hashcat_assist_prompt(),
            user_payload=hashcat_payload or self._build_hashcat_ai_payload(raw_input),
        )
        return self._normalize_hashcat_assist_payload(self._parse_json_content(content)), reasoning

    async def _assist_encoding_with_model(self, raw_input: str, mode: str) -> tuple[dict[str, Any], str]:
        content, reasoning = await self._request_json_completion(
            model=self.get_model_name(mode),
            system_prompt=self._encoding_assist_prompt(),
            user_payload=self._build_encoding_ai_payload(raw_input),
        )
        return self._normalize_encoding_assist_payload(self._parse_json_content(content), raw_input=raw_input), reasoning

    async def _assist_hash_result_with_model(
        self,
        raw_input: str,
        context: dict[str, Any],
        mode: str,
    ) -> tuple[dict[str, Any], str]:
        content, reasoning = await self._request_json_completion(
            model=self.get_model_name(mode),
            system_prompt=self._hash_result_assist_prompt(),
            user_payload={
                "user_input": raw_input,
                "hash_context": context,
                "output_requirement": "输出必须是 JSON，所有说明必须使用中文。",
            },
        )
        return self._normalize_hash_result_assist_payload(self._parse_json_content(content)), reasoning

    async def _assist_sqlite_result_with_model(
        self,
        raw_input: str,
        context: dict[str, Any],
        mode: str,
    ) -> tuple[dict[str, Any], str]:
        content, reasoning = await self._request_json_completion(
            model=self.get_model_name(mode),
            system_prompt=self._sqlite_assist_prompt(),
            user_payload={
                "user_input": raw_input,
                "sqlite_context": context,
                "output_requirement": "输出必须是 JSON，所有说明必须使用中文。",
            },
        )
        return self._normalize_sqlite_assist_payload(self._parse_json_content(content)), reasoning

    async def _request_json_completion(self, model: str, system_prompt: str, user_payload: dict[str, Any]) -> tuple[str, str]:
        payload = {
            "model": model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, indent=2)},
            ],
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.api_base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()
        message = response.json()["choices"][0]["message"]
        content, reasoning = self._extract_message_parts(message)
        if not content:
            raise ValueError("AI 返回内容为空。")
        return content, reasoning

    async def _stream_tool_result(
        self,
        tool_id: str,
        mode: str,
        normalizer: Callable[[dict[str, Any]], dict[str, Any]],
        fallback_factory: Callable[[str], dict[str, Any]],
        system_prompt: str,
        user_payload: dict[str, Any],
    ) -> AsyncIterator[dict[str, Any]]:
        self._refresh_config()
        model_name = self.get_model_name(mode)
        if not self.is_configured():
            fallback = fallback_factory("当前未配置外部 AI 服务。")
            yield {
                "type": "final",
                "tool_id": tool_id,
                "mode": mode,
                "model": model_name or None,
                "source": fallback["source"],
                "reasoning": "",
                "result": fallback["result"],
            }
            return

        try:
            reasoning_parts: list[str] = []
            content_parts: list[str] = []
            async for event in self._stream_json_completion(model_name, system_prompt, user_payload):
                if event["type"] == "reasoning":
                    reasoning_parts.append(event["delta"])
                    yield {
                        "type": "reasoning",
                        "tool_id": tool_id,
                        "delta": event["delta"],
                        "full_text": "".join(reasoning_parts),
                    }
                elif event["type"] == "content":
                    content_parts.append(event["delta"])
                    full_text = "".join(content_parts)
                    yield {
                        "type": "content",
                        "tool_id": tool_id,
                        "delta": event["delta"],
                        "full_text": full_text,
                        "preview": self._build_stream_preview(tool_id, full_text),
                    }
            yield {
                "type": "final",
                "tool_id": tool_id,
                "mode": mode,
                "model": model_name or None,
                "source": "ai",
                "reasoning": "".join(reasoning_parts),
                "result": normalizer(self._parse_json_content("".join(content_parts))),
            }
        except Exception as exc:  # noqa: BLE001
            fallback = fallback_factory(str(exc))
            yield {
                "type": "final",
                "tool_id": tool_id,
                "mode": mode,
                "model": model_name or None,
                "source": fallback["source"],
                "reasoning": "",
                "result": fallback["result"],
            }

    async def _stream_json_completion(
        self,
        model: str,
        system_prompt: str,
        user_payload: dict[str, Any],
    ) -> AsyncIterator[dict[str, str]]:
        payload = {
            "model": model,
            "stream": True,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, indent=2)},
            ],
        }
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "POST",
                f"{self.api_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                json=payload,
            ) as response:
                response.raise_for_status()
                pending_chunks: list[str] = []
                async for raw_line in response.aiter_lines():
                    line = raw_line.lstrip("\ufeff")
                    if not line:
                        for event in self._parse_stream_block("\n".join(pending_chunks)):
                            yield event
                        pending_chunks.clear()
                        continue
                    if line.startswith(":"):
                        continue
                    if line.startswith("data:"):
                        pending_chunks.append(line[5:].strip())
                        continue
                    pending_chunks.append(line.strip())

                for event in self._parse_stream_block("\n".join(pending_chunks)):
                    yield event

    def _extract_message_parts(self, message: Any) -> tuple[str, str]:
        if not isinstance(message, dict):
            raise ValueError("AI 返回 message 结构无效。")
        return (
            self._extract_text_delta(message.get("content")),
            self._extract_text_delta(message.get("reasoning_content") or message.get("reasoning")),
        )

    def _extract_text_delta(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            fragments: list[str] = []
            for item in value:
                if isinstance(item, str):
                    fragments.append(item)
                elif isinstance(item, dict):
                    text_value = item.get("text") or item.get("content")
                    if isinstance(text_value, str):
                        fragments.append(text_value)
            return "".join(fragments)
        if isinstance(value, dict):
            text_value = value.get("text") or value.get("content")
            if isinstance(text_value, str):
                return text_value
        return ""

    def _parse_stream_block(self, block: str) -> list[dict[str, str]]:
        cleaned_block = block.strip()
        if not cleaned_block or cleaned_block == "[DONE]":
            return []

        payload_lines = [line.strip() for line in cleaned_block.splitlines() if line.strip()]
        if not payload_lines:
            return []

        data = "\n".join(payload_lines)
        if data == "[DONE]":
            return []

        payload_data = json.loads(data)
        choices = payload_data.get("choices") or []
        if not choices:
            return []

        choice = choices[0] or {}
        delta = choice.get("delta") or {}
        message = choice.get("message") or {}
        reasoning_delta = self._extract_text_delta(
            delta.get("reasoning_content")
            or delta.get("reasoning")
            or delta.get("reasoning_text")
            or delta.get("reasoningText")
            or message.get("reasoning_content")
            or message.get("reasoning")
        )
        content_delta = self._extract_text_delta(
            delta.get("content")
            or delta.get("text")
            or delta.get("output_text")
            or message.get("content")
        )

        events: list[dict[str, str]] = []
        if reasoning_delta:
            events.append({"type": "reasoning", "delta": reasoning_delta})
        if content_delta:
            events.append({"type": "content", "delta": content_delta})
        return events

    def _build_stream_preview(self, tool_id: str, content: str) -> str:
        structured_preview = self._build_structured_stream_preview(tool_id, content)
        if structured_preview:
            return structured_preview

        key_candidates = ["summary", "explanation"]
        if tool_id in {"timestamp_parser", "hashcat_gui", "encoding_converter"}:
            key_candidates = ["explanation", "summary"]

        for key in key_candidates:
            match = re.search(rf'"{key}"\s*:\s*"((?:\\.|[^"])*)', content)
            if match and match.group(1):
                return self._sanitize_stream_preview(self._decode_json_fragment(match.group(1)))

        normalized = re.sub(r"\\u[0-9A-Fa-f]{4}", " ", content)
        normalized = normalized.replace("{", " ").replace("}", " ").replace("[", " ").replace("]", " ")
        normalized = normalized.replace('"', " ")
        normalized = re.sub(
            r"\b(?:summary|explanation|reasoning|findings|recommendations|timeline_summary|risk_level)\b\s*:",
            " ",
            normalized,
        )
        normalized = re.sub(r"[,:]+", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return self._sanitize_stream_preview(self._decode_json_fragment(normalized))

    def _decode_json_fragment(self, value: str) -> str:
        return (
            value.replace('\\"', '"')
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
        )

    def _sanitize_stream_preview(self, value: str) -> str:
        cleaned = value.replace("\r\n", "\n").replace("\ufeff", "").replace("\u200b", "").strip()
        return cleaned[:400]

    def _parse_json_content(self, content: str) -> dict[str, Any]:
        cleaned = content.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        return json.loads(cleaned.strip())

    def _build_evidence_bundle(self, parsed_result: ParsedLogResponse, question: str) -> dict[str, Any]:
        return {
            "question": question,
            "parsed_result": parsed_result.model_dump(),
            "evidence_constraints": [
                "仅依据输入证据做结论",
                "证据不足时明确写出不足之处",
                "所有 findings 都应包含 evidence",
            ],
        }

    def _build_hashcat_ai_payload(
        self,
        raw_input: str,
        *,
        file_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_context = context or {}
        runtime_context = dict(normalized_context.get("runtime") or {})
        hash_file_context = self._read_hashcat_file_context(file_id)
        default_wordlist_name, default_wordlist_path = self._resolve_hashcat_default_wordlist(normalized_context)

        runtime_context.setdefault("default_wordlist_name", default_wordlist_name)
        if default_wordlist_path:
            runtime_context.setdefault("default_wordlist_path", default_wordlist_path)

        return {
            "user_input": raw_input,
            "hashcat_context": {
                **normalized_context,
                "runtime": runtime_context,
                "hash_file": hash_file_context,
            },
            "output_requirement": (
                "输出必须是 JSON，explanation 和 warnings 必须使用中文。"
                "若无更强线索则默认使用 attack_mode=0，并把 wordlist_path 填为 rockyou.txt。"
                "attack_mode=1 时需要 secondary_wordlist_path。"
                "attack_mode=3 时只保留 mask。"
                "attack_mode=6 为字典加后缀掩码。"
                "attack_mode=7 为前缀掩码加字典。"
            ),
        }

    def _read_hashcat_file_context(self, file_id: str | None) -> dict[str, Any] | None:
        if not file_id:
            return None

        file_record = db_service.get_file(file_id)
        if not file_record:
            return None

        file_path = Path(str(file_record.get("file_path") or ""))
        if not file_path.is_file():
            return {
                "file_id": file_id,
                "original_name": file_record.get("original_name"),
                "size": file_record.get("size"),
                "created_at": file_record.get("created_at"),
                "sample_lines": [],
                "sample_hashes": [],
                "total_lines": 0,
                "non_empty_lines": 0,
            }

        sample_lines: list[str] = []
        sample_hashes: list[dict[str, Any]] = []
        total_lines = 0
        non_empty_lines = 0

        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                total_lines += 1
                stripped = line.strip()
                if not stripped:
                    continue
                non_empty_lines += 1
                if len(sample_lines) < 20:
                    sample_lines.append(stripped[:300])
                if len(sample_hashes) < 8:
                    candidate = self._extract_hex_hash(stripped)
                    if candidate:
                        sample_hashes.append({"value": candidate, "length": len(candidate)})

        return {
            "file_id": file_id,
            "original_name": file_record.get("original_name"),
            "size": file_record.get("size"),
            "created_at": file_record.get("created_at"),
            "sample_lines": sample_lines,
            "sample_hashes": sample_hashes,
            "total_lines": total_lines,
            "non_empty_lines": non_empty_lines,
        }

    def _resolve_hashcat_default_wordlist(self, context: dict[str, Any] | None = None) -> tuple[str, str | None]:
        runtime_context = (context or {}).get("runtime") if isinstance(context, dict) else {}
        if not isinstance(runtime_context, dict):
            runtime_context = {}

        default_wordlist = hashcat_service.get_default_wordlist()
        if default_wordlist:
            return default_wordlist.name, str(default_wordlist.resolve())

        default_name = runtime_context.get("default_wordlist_name")
        default_path = runtime_context.get("default_wordlist_path")
        if isinstance(default_name, str) and default_name.strip():
            return default_name.strip(), str(default_path).strip() if isinstance(default_path, str) and default_path.strip() else None

        return "rockyou.txt", None

    def _build_structured_stream_preview(self, tool_id: str, content: str) -> str:
        field_map: dict[str, list[tuple[str, str]]] = {
            "log_parser": [("风险等级", "risk_level"), ("摘要", "summary")],
            "timestamp_parser": [
                ("时间戳", "timestamp"),
                ("类型", "timestamp_type"),
                ("源时区", "origin_timezone"),
                ("目标时区", "target_timezone"),
                ("说明", "explanation"),
            ],
            "hashcat_gui": [
                ("Hash 模式", "hash_mode"),
                ("攻击模式", "attack_mode"),
                ("字典", "wordlist_path"),
                ("第二字典", "secondary_wordlist_path"),
                ("掩码", "mask"),
                ("说明", "explanation"),
            ],
            "encoding_converter": [("推荐编码", "recommended_encoding"), ("说明", "explanation")],
            "hash_tool": [("主哈希", "primary_hash"), ("摘要", "summary")],
            "sqlite2csv": [("当前表", "current_table_name"), ("摘要", "summary")],
        }
        specs = field_map.get(tool_id) or []
        if not specs:
            return ""

        preview_lines: list[str] = []
        for label, key in specs:
            value = self._extract_partial_json_value(content, key)
            if value:
                preview_lines.append(f"{label}：{value}")

        if not preview_lines:
            return ""
        return self._sanitize_stream_preview("\n".join(preview_lines))

    def _extract_partial_json_value(self, content: str, key: str) -> str:
        string_match = re.search(rf'"{key}"\s*:\s*"((?:\\.|[^"])*)', content)
        if string_match and string_match.group(1):
            return self._sanitize_stream_preview(self._decode_json_fragment(string_match.group(1)))

        number_match = re.search(rf'"{key}"\s*:\s*(-?\d+(?:\.\d+)?)', content)
        if number_match:
            return number_match.group(1)

        literal_match = re.search(rf'"{key}"\s*:\s*(true|false|null)', content, flags=re.IGNORECASE)
        if literal_match:
            return literal_match.group(1).lower()

        return ""

    def _normalize_strategy_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "log_type": str(payload.get("log_type") or payload.get("log_format") or "generic-text-log"),
            "overview": str(
                payload.get("overview")
                or payload.get("summary")
                or payload.get("description")
                or "这是一份通用文本日志，主要记录运行状态和事件过程。"
            ),
            "error_keywords": self._coerce_keyword_list(payload.get("error_keywords") or payload.get("error_terms")),
            "warning_keywords": self._coerce_keyword_list(
                payload.get("warning_keywords") or payload.get("warning_terms")
            ),
            "info_keywords": self._coerce_keyword_list(payload.get("info_keywords") or payload.get("info_terms")),
            "fragment_keywords": self._coerce_keyword_list(
                payload.get("fragment_keywords") or payload.get("critical_keywords") or payload.get("highlight_keywords")
            ),
            "notes": self._coerce_text_list(payload.get("notes")),
        }

    def _normalize_analysis_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        findings_raw = payload.get("findings") or payload.get("key_findings") or []
        if isinstance(findings_raw, dict):
            findings_raw = list(findings_raw.values())
        if not isinstance(findings_raw, list):
            findings_raw = [findings_raw]

        findings: list[dict[str, Any]] = []
        for item in findings_raw:
            if isinstance(item, str):
                findings.append({"title": item[:50] or "发现项", "evidence": [item], "explanation": item})
                continue
            if not isinstance(item, dict):
                continue
            findings.append(
                {
                    "title": str(item.get("title") or item.get("finding") or item.get("name") or "发现项"),
                    "evidence": self._coerce_evidence_list(
                        item.get("evidence") or item.get("proof") or item.get("supporting_evidence")
                    ),
                    "explanation": self._optional_text(
                        item.get("explanation")
                        or item.get("detail")
                        or item.get("analysis")
                        or item.get("finding")
                    )
                    or "",
                }
            )

        risk_level = str(payload.get("risk_level") or "medium").lower()
        if risk_level not in {"low", "medium", "high"}:
            risk_level = "medium"

        return {
            "summary": str(payload.get("summary") or "AI 未返回明确摘要。"),
            "risk_level": risk_level,
            "findings": findings,
            "timeline_summary": self._coerce_text_list(
                payload.get("timeline_summary") or payload.get("timeline") or payload.get("timeline_highlights")
            ),
            "recommendations": self._coerce_text_list(
                payload.get("recommendations") or payload.get("actions") or payload.get("next_steps")
            ),
        }

    def _normalize_timestamp_assist_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        timestamp_type = str(payload.get("timestamp_type") or "auto").strip()
        if timestamp_type not in SUPPORTED_TIMESTAMP_TYPES:
            timestamp_type = "unix"

        origin_timezone = str(payload.get("origin_timezone") or "Asia/Shanghai").strip() or "Asia/Shanghai"
        target_timezone = str(payload.get("target_timezone") or "Asia/Shanghai").strip() or "Asia/Shanghai"
        if origin_timezone not in SUPPORTED_TIMEZONES:
            origin_timezone = "Asia/Shanghai"
        if target_timezone not in SUPPORTED_TIMEZONES:
            target_timezone = "Asia/Shanghai"

        return {
            "timestamp": str(payload.get("timestamp") or "").strip(),
            "timestamp_type": timestamp_type,
            "origin_timezone": origin_timezone,
            "target_timezone": target_timezone,
            "explanation": str(payload.get("explanation") or "已按当前输入给出最可能的时间戳识别结果。"),
            "confidence": str(payload.get("confidence") or "medium").strip().lower(),
            "warnings": self._coerce_text_list(payload.get("warnings")),
        }

    def _normalize_hashcat_assist_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        attack_mode = payload.get("attack_mode", 0)
        try:
            attack_mode_value = int(attack_mode)
        except (TypeError, ValueError):
            attack_mode_value = 0
        if attack_mode_value not in {0, 1, 3, 6, 7}:
            attack_mode_value = 0

        extra_args = payload.get("extra_args")
        if isinstance(extra_args, str):
            extra_args = [part for part in re.split(r"\s+", extra_args.strip()) if part]
        elif not isinstance(extra_args, list):
            extra_args = []

        hash_mode = payload.get("hash_mode", 0)
        try:
            hash_mode_value = int(hash_mode)
        except (TypeError, ValueError):
            hash_mode_value = 0

        wordlist_path = self._optional_text(payload.get("wordlist_path"))
        secondary_wordlist_path = self._optional_text(payload.get("secondary_wordlist_path"))
        mask = self._optional_text(payload.get("mask"))
        warnings = self._coerce_text_list(payload.get("warnings"))
        if attack_mode_value == 3:
            wordlist_path = None
            secondary_wordlist_path = None
        elif attack_mode_value == 1:
            mask = None
            if not wordlist_path:
                wordlist_path = "rockyou.txt"
        elif attack_mode_value in {6, 7}:
            secondary_wordlist_path = None
            if not wordlist_path:
                wordlist_path = "rockyou.txt"
        else:
            secondary_wordlist_path = None
            mask = None
            if not wordlist_path:
                wordlist_path = "rockyou.txt"

        if attack_mode_value != 1:
            secondary_wordlist_path = None
        if attack_mode_value not in {3, 6, 7}:
            mask = None
        if attack_mode_value == 1 and not secondary_wordlist_path:
            warnings.append("组合模式需要第二个字典，请补充 secondary_wordlist_path 或上传第二字典。")
        if attack_mode_value in {3, 6, 7} and not mask:
            warnings.append("当前攻击模式需要 mask，请补充掩码后再启动任务。")

        return {
            "hash_mode": hash_mode_value,
            "attack_mode": attack_mode_value,
            "wordlist_path": wordlist_path,
            "secondary_wordlist_path": secondary_wordlist_path,
            "mask": mask,
            "session_name": self._optional_text(payload.get("session_name")),
            "extra_args": [str(item).strip() for item in extra_args if str(item).strip()],
            "explanation": str(payload.get("explanation") or "已按当前输入给出最可能的 Hashcat 配置建议。"),
            "confidence": str(payload.get("confidence") or "medium").strip().lower(),
            "warnings": warnings,
        }

    def _normalize_encoding_assist_payload(self, payload: dict[str, Any], raw_input: str | None = None) -> dict[str, Any]:
        local_analysis = self._analyze_encoding_input(raw_input or self._optional_text(payload.get("cyberchef_input") or payload.get("input")) or "")
        recommended_encoding = (
            str(payload.get("recommended_encoding") or payload.get("encoding") or local_analysis["recommended_encoding"]).strip()
            or local_analysis["recommended_encoding"]
        )
        recipe_field = payload.get("recipe")
        suggested_recipe_source = payload.get("suggested_recipe")
        if suggested_recipe_source is None and not self._looks_like_cyberchef_recipe(recipe_field):
            suggested_recipe_source = recipe_field
        suggested_recipe = self._coerce_recipe_steps(suggested_recipe_source)
        if not suggested_recipe:
            suggested_recipe = list(local_analysis["suggested_recipe"])
        candidates_raw = payload.get("candidates") or []
        if not isinstance(candidates_raw, list):
            candidates_raw = [candidates_raw]

        candidates: list[dict[str, Any]] = []
        for item in candidates_raw:
            if isinstance(item, str):
                candidates.append(
                    {
                        "name": item,
                        "confidence": "low",
                        "score": 35,
                        "reason": "模型返回了候选名称，但未提供更详细的依据。",
                    }
                )
                continue
            if not isinstance(item, dict):
                continue

            score = item.get("score", 50)
            try:
                score_value = max(0, min(100, int(score)))
            except (TypeError, ValueError):
                score_value = 50

            candidates.append(
                {
                    "name": str(item.get("name") or item.get("encoding") or "未知编码"),
                    "confidence": str(item.get("confidence") or self._score_to_confidence(score_value)).strip().lower(),
                    "score": score_value,
                    "reason": str(item.get("reason") or item.get("explanation") or "未提供判断依据。"),
                }
            )

        if not candidates:
            candidates = list(local_analysis["candidates"])
        candidates = self._dedupe_encoding_candidates(candidates)
        if not candidates:
            candidates = list(local_analysis["candidates"])

        cyberchef_recipe = self._optional_text(payload.get("cyberchef_recipe"))
        if not cyberchef_recipe and self._looks_like_cyberchef_recipe(recipe_field):
            cyberchef_recipe = str(recipe_field).strip()
        if not cyberchef_recipe:
            cyberchef_recipe = self._build_cyberchef_recipe_from_suggestions(suggested_recipe, recommended_encoding)
        if not cyberchef_recipe:
            cyberchef_recipe = local_analysis["cyberchef_recipe"]

        cyberchef_input = self._optional_text(payload.get("cyberchef_input") or payload.get("input"))
        if raw_input and not cyberchef_input:
            cyberchef_input = raw_input.strip()
        if not cyberchef_input:
            cyberchef_input = local_analysis["cyberchef_input"]

        return {
            "recommended_encoding": recommended_encoding,
            "candidates": candidates,
            "suggested_recipe": suggested_recipe,
            "cyberchef_recipe": cyberchef_recipe,
            "cyberchef_input": cyberchef_input,
            "explanation": str(payload.get("explanation") or local_analysis["explanation"] or "已根据当前输入给出最可能的编码判断和 CyberChef 建议。"),
            "warnings": self._merge_text_lists(self._coerce_text_list(payload.get("warnings")), local_analysis["warnings"]),
        }

    def _looks_like_cyberchef_recipe(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        return bool(re.search(r"[A-Za-z][A-Za-z0-9_]*\(", value.strip()))

    def _coerce_recipe_steps(self, value: Any) -> list[str]:
        raw_items: list[str] = []
        if isinstance(value, list):
            raw_items = [str(item).strip() for item in value if str(item).strip()]
        elif isinstance(value, str):
            raw_items = [value.strip()] if value.strip() else []
        elif value is not None:
            text = str(value).strip()
            raw_items = [text] if text else []

        steps: list[str] = []
        for item in raw_items:
            if self._looks_like_cyberchef_recipe(item):
                operations = re.findall(r"[A-Za-z][A-Za-z0-9_]*\([^)]*\)", item)
                if operations:
                    steps.extend(operations)
                    continue
            for part in re.split(r"\s*(?:->|=>|→)\s*", item):
                for fragment in re.split(r"[\n\r;；,，]+", part):
                    step = fragment.strip()
                    if step:
                        steps.append(step)
        return list(dict.fromkeys(steps))

    def _build_cyberchef_recipe_from_suggestions(
        self,
        suggested_recipe: list[str],
        recommended_encoding: str,
    ) -> str | None:
        recipe_parts: list[str] = []
        for item in self._coerce_recipe_steps(suggested_recipe):
            recipe_part = self._suggestion_to_cyberchef_recipe_part(item, recommended_encoding)
            if recipe_part:
                recipe_parts.append(recipe_part)

        if recipe_parts:
            return "".join(dict.fromkeys(recipe_parts))

        return self._encoding_to_cyberchef_decode_recipe(recommended_encoding)

    def _suggestion_to_cyberchef_recipe_part(self, step: str, recommended_encoding: str) -> str | None:
        if self._looks_like_cyberchef_recipe(step):
            return step.strip()

        normalized = re.sub(r"\s+", " ", step).strip().lower()
        if not normalized:
            return None

        if normalized in {"decode text", "from utf8", "from utf-8"}:
            return self._encoding_to_cyberchef_decode_recipe(recommended_encoding)

        suggested_map = {
            "hex": "From_Hex('Auto')",
            "from hex": "From_Hex('Auto')",
            "base64": "From_Base64('A-Za-z0-9+/=',true,false)",
            "from base64": "From_Base64('A-Za-z0-9+/=',true,false)",
            "base32": "From_Base32('A-Z2-7=',false)",
            "from base32": "From_Base32('A-Z2-7=',false)",
            "url": "URL_Decode()",
            "url decode": "URL_Decode()",
            "unicode escape": "Unescape_Unicode_Characters()",
            "unescape unicode characters": "Unescape_Unicode_Characters()",
            "html entity": "From_HTML_Entity()",
            "from html entity": "From_HTML_Entity()",
        }
        return suggested_map.get(normalized)

    def _encoding_to_cyberchef_decode_recipe(self, recommended_encoding: str) -> str | None:
        normalized = recommended_encoding.strip().lower()
        encoding_map = {
            "utf-8": "Decode_text('UTF-8 (65001)')",
            "utf8": "Decode_text('UTF-8 (65001)')",
            "gbk": "Decode_text('GBK (936)')",
            "gb18030": "Decode_text('GB18030 (54936)')",
            "utf-16": "Decode_text('UTF-16LE (1200)')",
            "utf-16le": "Decode_text('UTF-16LE (1200)')",
            "utf-16be": "Decode_text('UTF-16BE (1201)')",
        }
        return encoding_map.get(normalized)

    def _analyze_encoding_input(self, raw_input: str) -> dict[str, Any]:
        text = raw_input.strip()
        compact = re.sub(r"\s+", "", text)
        lowered = text.lower()
        warnings: list[str] = []
        candidates: list[dict[str, Any]] = []

        def add_candidate(name: str, score: int, reason: str) -> None:
            candidates.append(
                {
                    "name": name,
                    "score": score,
                    "confidence": self._score_to_confidence(score),
                    "reason": reason,
                }
            )

        base64_probe = self._probe_base64_text(text)
        if base64_probe["score"] > 0:
            add_candidate("Base64", base64_probe["score"], base64_probe["reason"])

        base32_probe = self._probe_base32_text(text)
        if base32_probe["score"] > 0:
            add_candidate("Base32", base32_probe["score"], base32_probe["reason"])

        if compact and re.fullmatch(r"[A-Fa-f0-9]+", compact) and len(compact) >= 8 and len(compact) % 2 == 0:
            hex_preview = self._decode_hex_text(compact)
            reason = "输入几乎完全由十六进制字符组成，适合优先尝试 From Hex。"
            if hex_preview:
                reason = f"{reason} 试解码后可得到可读文本片段：{self._truncate_encoding_preview(hex_preview)}。"
            add_candidate("Hex", 92 if hex_preview else 88, reason)

        percent_hits = re.findall(r"%[0-9A-Fa-f]{2}", text)
        if percent_hits:
            decoded_url = unquote(text)
            score = 84 if len(percent_hits) < 2 else 90
            reason = f"输入中包含 {len(percent_hits)} 个 %xx 片段，典型于 URL 编码。"
            if decoded_url != text:
                reason = f"{reason} 试解码后片段为：{self._truncate_encoding_preview(decoded_url)}。"
            add_candidate("URL", score, reason)

        if "\\u" in text and re.search(r"\\u[0-9A-Fa-f]{4}", text):
            unicode_preview = self._decode_unicode_escape_text(text)
            reason = "输入包含明显的 \\uXXXX 转义序列。"
            if unicode_preview:
                reason = f"{reason} 试解码后片段为：{self._truncate_encoding_preview(unicode_preview)}。"
            add_candidate("Unicode Escape", 91, reason)

        if "&#" in text or "&amp;" in lowered or re.search(r"&[A-Za-z]{2,10};", text):
            html_preview = html.unescape(text)
            reason = "输入包含 HTML 实体编码特征。"
            if html_preview != text:
                reason = f"{reason} 试解码后片段为：{self._truncate_encoding_preview(html_preview)}。"
            add_candidate("HTML Entity", 86, reason)

        if re.search(r"\\[\"\\/bfnrt]", text) or re.search(r"\\u[0-9A-Fa-f]{4}", text):
            json_preview = self._decode_json_escape_text(text)
            reason = "输入中包含 JSON 风格的反斜杠转义序列。"
            if json_preview and json_preview != text:
                reason = f"{reason} 试解码后片段为：{self._truncate_encoding_preview(json_preview)}。"
            add_candidate("JSON Escape", 78, reason)

        if not candidates:
            add_candidate("UTF-8", 58, "当前更像是普通文本，优先按 UTF-8 或多字节字符集排查。")
            add_candidate("GB18030", 52, "若出现中文乱码，GB18030/GBK 与 UTF-8 互转是常见原因。")

        if any(token in text for token in ["Ã", "ä", "å", "æ", "ï", "�"]):
            add_candidate("UTF-8", 72, "检测到常见乱码特征，可能是 UTF-8 被按其他编码错误解读。")
            add_candidate("GBK", 64, "中文场景下也可能是 GBK/GB18030 与 UTF-8 之间的误解码。")
            warnings.append("当前更像是乱码排查场景，请结合原始来源和上下文在 CyberChef 中交叉验证。")

        candidates = self._dedupe_encoding_candidates(candidates)
        recipe_steps, decoded_layers = self._discover_encoding_recipe(text)

        if base64_probe["score"] >= 78 and base32_probe["score"] >= 78 and abs(base64_probe["score"] - base32_probe["score"]) <= 10:
            warnings.append("当前同时命中 Base32 和 Base64 特征，请优先结合字符集差异与试解码结果人工复核。")

        if not recipe_steps:
            recommended_name = candidates[0]["name"] if candidates else "UTF-8"
            fallback_step = self._encoding_step_name(recommended_name)
            if fallback_step:
                recipe_steps = [fallback_step]
            elif recommended_name in {"UTF-8", "GBK", "GB18030", "UTF-16LE", "UTF-16BE"}:
                recipe_steps = ["Decode text"]

        recommended = candidates[0]["name"] if candidates else "UTF-8"
        if len(recipe_steps) >= 2:
            explanation = (
                "检测到更像多层编码包装，已按字符集、padding 与试解码结果给出分层 CyberChef 配方。"
            )
        elif recommended in {"Base64", "Base32", "Hex", "URL", "Unicode Escape", "HTML Entity", "JSON Escape"}:
            explanation = "已根据字符集、转义模式和试解码结果给出最可能的编码判断。"
        else:
            explanation = "已根据当前文本特征给出最可能的编码或乱码排查方向。"

        return {
            "recommended_encoding": recommended,
            "candidates": candidates[:5],
            "suggested_recipe": recipe_steps,
            "cyberchef_recipe": self._build_cyberchef_recipe_from_suggestions(recipe_steps, recommended),
            "cyberchef_input": text,
            "explanation": explanation,
            "warnings": self._merge_text_lists(warnings),
            "evidence": {
                "trimmed_length": len(text),
                "compact_length": len(compact),
                "contains_whitespace": bool(re.search(r"\s", text)),
                "base64_probe": {key: value for key, value in base64_probe.items() if key != "decoded_text"},
                "base32_probe": {key: value for key, value in base32_probe.items() if key != "decoded_text"},
                "decoded_layers": decoded_layers,
                "candidate_summary": candidates[:5],
            },
        }

    def _probe_base64_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 54
        reasons = ["字符集满足 Base64 的常见取值范围。"]
        if len(compact) % 4 == 0:
            score += 8
            reasons.append("长度满足 Base64 常见的 4 字节分组。")
        if re.search(r"\s", text):
            score -= 18
            reasons.append("存在空白分隔，更像普通文本而不是单段 Base64 串。")
        if any(ch in compact for ch in "+/_-"):
            score += 10
            reasons.append("包含 Base64 常见的符号字符。")
        if any(ch.islower() for ch in compact):
            score += 6
            reasons.append("包含小写字母，更接近 Base64 而不是标准 Base32。")
        if re.fullmatch(r"[A-Z2-7=]+", compact.upper()) and not any(ch in compact for ch in "+/_-") and not any(ch.islower() for ch in compact):
            score -= 14
            reasons.append("字符集也高度接近 Base32，因此存在歧义。")

        decoded_text = self._decode_base64_text(compact)
        if decoded_text:
            score += 18
            reasons.append(f"尝试 Base64 解码后得到可读片段：{self._truncate_encoding_preview(decoded_text)}。")
            nested_hint = self._best_nested_encoding_hint(decoded_text)
            if nested_hint:
                score += 6
                reasons.append(f"解码后一层仍明显像 {nested_hint}。")

        return {
            "score": max(0, min(100, score)),
            "reason": " ".join(reasons),
            "decoded_text": decoded_text,
            "preview": self._truncate_encoding_preview(decoded_text) if decoded_text else "",
        }

    def _probe_base32_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        upper_text = compact.upper()
        if len(compact) < 8 or not re.fullmatch(r"[A-Z2-7=]+", upper_text):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 58
        reasons = ["字符集主要由 A-Z、2-7 和 = 组成，接近 Base32。"]
        if re.search(r"\s", text):
            score -= 18
            reasons.append("存在空白分隔，更像普通文本而不是单段 Base32 串。")
        if not any(ch in compact for ch in "+/_-"):
            score += 8
            reasons.append("未出现 +、/、_、- 等更常见于 Base64 的符号。")
        if len(upper_text) % 8 == 0 or "=" in upper_text:
            score += 8
            reasons.append("长度或 padding 形态符合 Base32 常见分组特征。")
        if any(ch.islower() for ch in compact):
            score -= 4
            reasons.append("输入使用了小写形式，虽然仍可能是 Base32，但不如大写标准写法典型。")

        decoded_text = self._decode_base32_text(upper_text)
        if decoded_text:
            score += 18
            reasons.append(f"尝试 Base32 解码后得到可读片段：{self._truncate_encoding_preview(decoded_text)}。")
            nested_hint = self._best_nested_encoding_hint(decoded_text)
            if nested_hint:
                score += 6
                reasons.append(f"解码后一层仍明显像 {nested_hint}。")

        return {
            "score": max(0, min(100, score)),
            "reason": " ".join(reasons),
            "decoded_text": decoded_text,
            "preview": self._truncate_encoding_preview(decoded_text) if decoded_text else "",
        }

    def _discover_encoding_recipe(self, text: str, max_depth: int = 2) -> tuple[list[str], list[dict[str, Any]]]:
        steps: list[str] = []
        decoded_layers: list[dict[str, Any]] = []
        current_text = text.strip()
        seen: set[str] = {current_text}

        for _ in range(max_depth):
            probe = self._best_structured_encoding_probe(current_text)
            if not probe:
                break
            step_name = self._encoding_step_name(str(probe["name"]))
            decoded_text = str(probe.get("decoded_text") or "").strip()
            if not step_name or not decoded_text or decoded_text in seen:
                break
            steps.append(step_name)
            decoded_layers.append(
                {
                    "encoding": probe["name"],
                    "score": probe["score"],
                    "preview": self._truncate_encoding_preview(decoded_text),
                }
            )
            seen.add(decoded_text)
            current_text = decoded_text

        return steps, decoded_layers

    def _best_structured_encoding_probe(self, text: str) -> dict[str, Any] | None:
        candidates: list[dict[str, Any]] = []
        base64_probe = self._probe_base64_text(text)
        if base64_probe["score"] >= 80 and base64_probe.get("decoded_text"):
            candidates.append({"name": "Base64", **base64_probe})

        base32_probe = self._probe_base32_text(text)
        if base32_probe["score"] >= 80 and base32_probe.get("decoded_text"):
            candidates.append({"name": "Base32", **base32_probe})

        compact = re.sub(r"\s+", "", text)
        if compact and re.fullmatch(r"[A-Fa-f0-9]+", compact) and len(compact) >= 8 and len(compact) % 2 == 0:
            decoded_hex = self._decode_hex_text(compact)
            if decoded_hex:
                candidates.append({"name": "Hex", "score": 88, "reason": "十六进制试解码成功。", "decoded_text": decoded_hex})

        decoded_url = unquote(text)
        if decoded_url != text and re.search(r"%[0-9A-Fa-f]{2}", text):
            candidates.append({"name": "URL", "score": 86, "reason": "URL 解码后内容发生变化。", "decoded_text": decoded_url})

        decoded_unicode = self._decode_unicode_escape_text(text)
        if decoded_unicode and decoded_unicode != text and re.search(r"\\u[0-9A-Fa-f]{4}", text):
            candidates.append({"name": "Unicode Escape", "score": 86, "reason": "Unicode 转义解码后内容发生变化。", "decoded_text": decoded_unicode})

        decoded_html = html.unescape(text)
        if decoded_html != text and ("&#" in text or "&amp;" in text.lower() or re.search(r"&[A-Za-z]{2,10};", text)):
            candidates.append({"name": "HTML Entity", "score": 82, "reason": "HTML 实体解码后内容发生变化。", "decoded_text": decoded_html})

        decoded_json = self._decode_json_escape_text(text)
        if decoded_json and decoded_json != text and re.search(r"\\[\"\\/bfnrt]", text):
            candidates.append({"name": "JSON Escape", "score": 80, "reason": "JSON 转义解码后内容发生变化。", "decoded_text": decoded_json})

        if not candidates:
            return None
        return max(candidates, key=lambda item: int(item["score"]))

    def _best_nested_encoding_hint(self, text: str) -> str | None:
        probe = self._best_structured_encoding_probe(text)
        if not probe:
            return None
        return str(probe["name"])

    def _encoding_step_name(self, encoding_name: str) -> str | None:
        normalized = encoding_name.strip().lower()
        mapping = {
            "base64": "From Base64",
            "base32": "From Base32",
            "hex": "From Hex",
            "url": "URL Decode",
            "unicode escape": "Unescape Unicode Characters",
            "html entity": "From HTML Entity",
        }
        if normalized in {"utf-8", "utf8", "gbk", "gb18030", "utf-16", "utf-16le", "utf-16be"}:
            return "Decode text"
        return mapping.get(normalized)

    def _decode_base64_text(self, value: str) -> str | None:
        normalized = value.replace("-", "+").replace("_", "/")
        padded = normalized + ("=" * (-len(normalized) % 4))
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return None
        return self._decode_bytes_to_text(decoded)

    def _decode_base32_text(self, value: str) -> str | None:
        normalized = value.upper()
        padded = normalized + ("=" * (-len(normalized) % 8))
        try:
            decoded = base64.b32decode(padded, casefold=True)
        except (binascii.Error, ValueError):
            return None
        return self._decode_bytes_to_text(decoded)

    def _decode_hex_text(self, value: str) -> str | None:
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            return None
        return self._decode_bytes_to_text(decoded)

    def _decode_unicode_escape_text(self, value: str) -> str | None:
        try:
            decoded = value.encode("utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return None
        return decoded if decoded and decoded != value else None

    def _decode_json_escape_text(self, value: str) -> str | None:
        try:
            decoded = value.encode("utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return None
        return decoded if decoded and decoded != value else None

    def _decode_bytes_to_text(self, value: bytes) -> str | None:
        if not value:
            return None

        best_text = ""
        best_ratio = 0.0
        for encoding in ("utf-8", "utf-16le", "utf-16be", "gb18030", "latin-1"):
            try:
                decoded = value.decode(encoding)
            except UnicodeDecodeError:
                continue
            cleaned = decoded.strip("\x00")
            if not cleaned:
                continue
            ratio = self._text_printable_ratio(cleaned)
            if ratio > best_ratio:
                best_text = cleaned
                best_ratio = ratio

        if best_text and best_ratio >= 0.55:
            return best_text
        return None

    def _text_printable_ratio(self, value: str) -> float:
        if not value:
            return 0.0
        printable_count = 0
        for char in value:
            if char in "\n\r\t" or char.isprintable():
                printable_count += 1
        return printable_count / len(value)

    def _truncate_encoding_preview(self, value: str | None, limit: int = 48) -> str:
        preview = self._optional_text(value)
        if not preview:
            return ""
        normalized = re.sub(r"\s+", " ", preview)
        if len(normalized) <= limit:
            return normalized
        return f"{normalized[:limit]}..."

    def _merge_text_lists(self, *groups: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for group in groups:
            for item in group:
                normalized = str(item).strip()
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                merged.append(normalized)
        return merged

    def _dedupe_encoding_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        bucket: dict[str, dict[str, Any]] = {}
        for item in candidates:
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            score_value = item.get("score", 50)
            try:
                score = max(0, min(100, int(score_value)))
            except (TypeError, ValueError):
                score = 50
            reason = str(item.get("reason") or "未提供判断依据。").strip()
            existing = bucket.get(name)
            if not existing or score > int(existing["score"]):
                bucket[name] = {
                    "name": name,
                    "score": score,
                    "confidence": str(item.get("confidence") or self._score_to_confidence(score)).strip().lower(),
                    "reason": reason,
                }
                continue
            if reason and reason not in str(existing["reason"]):
                existing["reason"] = f"{existing['reason']} {reason}".strip()

        deduped = list(bucket.values())
        deduped.sort(key=lambda item: int(item["score"]), reverse=True)
        return deduped

    def _normalize_hash_result_assist_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        primary_hash = str(payload.get("primary_hash") or payload.get("preferred_hash") or "SHA256").strip() or "SHA256"
        confidence = str(payload.get("confidence") or "medium").strip().lower() or "medium"
        return {
            "summary": str(payload.get("summary") or "已根据当前哈希结果生成分析建议。"),
            "primary_hash": primary_hash,
            "findings": self._coerce_text_list(payload.get("findings") or payload.get("highlights")),
            "recommendations": self._coerce_text_list(payload.get("recommendations") or payload.get("next_steps")),
            "warnings": self._coerce_text_list(payload.get("warnings")),
            "confidence": confidence,
        }

    def _normalize_sqlite_assist_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        highlighted_raw = payload.get("highlighted_tables") or payload.get("priority_tables") or []
        if not isinstance(highlighted_raw, list):
            highlighted_raw = [highlighted_raw]

        highlighted_tables: list[dict[str, Any]] = []
        for item in highlighted_raw:
            if isinstance(item, str):
                highlighted_tables.append(
                    {
                        "table_name": item,
                        "priority": "medium",
                        "reason": "模型返回了表名，但没有补充更多依据。",
                    }
                )
                continue
            if not isinstance(item, dict):
                continue
            priority = str(item.get("priority") or "medium").strip().lower()
            if priority not in {"high", "medium", "low"}:
                priority = "medium"
            highlighted_tables.append(
                {
                    "table_name": str(item.get("table_name") or item.get("name") or "未命名表"),
                    "priority": priority,
                    "reason": str(item.get("reason") or item.get("explanation") or "模型未补充具体依据。"),
                }
            )

        return {
            "summary": str(payload.get("summary") or "已根据当前数据库结构生成分析建议。"),
            "highlighted_tables": highlighted_tables,
            "current_table_name": self._optional_text(payload.get("current_table_name") or payload.get("selected_table")),
            "focus_fields": self._coerce_text_list(payload.get("focus_fields") or payload.get("important_fields")),
            "schema_notes": self._coerce_text_list(payload.get("schema_notes") or payload.get("observations")),
            "recommendations": self._coerce_text_list(payload.get("recommendations") or payload.get("next_steps")),
            "warnings": self._coerce_text_list(payload.get("warnings")),
        }

    def _coerce_keyword_list(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            parts = re.split(r"[,，\n\r]+", value)
            return [item.strip() for item in parts if item.strip()]
        return []

    def _coerce_text_list(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            parts = re.split(r"[\n\r;；]+", value)
            cleaned = [item.strip() for item in parts if item.strip()]
            return cleaned or [value.strip()]
        return []

    def _coerce_evidence_list(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    def _optional_text(self, value: Any) -> str | None:
        text = str(value).strip() if value is not None else ""
        return text or None

    def _fallback_stream_payload(self, result: dict[str, Any], error: str) -> dict[str, Any]:
        warnings = list(result.get("warnings") or [])
        warnings.append(f"外部 AI 流式调用失败，已切换为本地识别。原因：{error}")
        result["warnings"] = warnings
        return {"source": "fallback", "result": result}

    def _assist_timestamp_fallback(self, raw_input: str) -> dict[str, Any]:
        text = raw_input.strip()
        warnings: list[str] = []
        number_match = re.search(r"[-+]?\d+(?:\.\d+)?", text)
        timestamp = number_match.group(0) if number_match else ""

        lowered = text.lower()
        if "filetime" in lowered or "windows" in lowered:
            timestamp_type = "windows_filetime"
        elif "webkit" in lowered or "chrome" in lowered:
            timestamp_type = "chrome_webkit"
        elif "apple absolute" in lowered or "cocoa" in lowered:
            timestamp_type = "apple_absolute_time"
        elif "ios" in lowered:
            timestamp_type = "ios"
        elif "tick" in lowered or ".net" in lowered:
            timestamp_type = "dotnet_ticks"
        else:
            timestamp_type = self._guess_timestamp_type_from_value(timestamp)

        origin_timezone = next((tz for tz in SUPPORTED_TIMEZONES if tz.lower() in lowered), "Asia/Shanghai")
        target_timezone = "Asia/Shanghai"

        if not timestamp:
            warnings.append("未从输入中提取到明确数字，请手动检查时间戳内容。")
        if timestamp_type == "unix" and timestamp and len(timestamp.split(".")[0]) not in {10, 13, 16, 19}:
            warnings.append("当前按 UNIX 类时间戳处理，但长度并不典型，请人工复核。")

        return {
            "timestamp": timestamp,
            "timestamp_type": timestamp_type,
            "origin_timezone": origin_timezone,
            "target_timezone": target_timezone,
            "explanation": "已根据输入中的数字长度、关键字和时区线索给出最可能的时间戳配置。",
            "confidence": "medium" if warnings else "high",
            "warnings": warnings,
        }

    def _assist_hashcat_fallback(
        self,
        raw_input: str,
        *,
        context: dict[str, Any] | None = None,
        file_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        text = raw_input.strip()
        normalized_context = context or {}
        file_context = file_context or {}
        sample_lines = file_context.get("sample_lines") if isinstance(file_context.get("sample_lines"), list) else []
        sample_hashes = file_context.get("sample_hashes") if isinstance(file_context.get("sample_hashes"), list) else []
        combined_text = "\n".join([text, *[str(item) for item in sample_lines[:5]]]).strip()
        lowered = combined_text.lower()
        warnings: list[str] = []

        mask_match = re.search(r"(\?[aludhsHbB\?]){2,}", combined_text)
        path_match = re.search(r"(?:[A-Za-z]:\\|/)[^\r\n\"']+", text)
        current_form = normalized_context.get("current_form") if isinstance(normalized_context, dict) else {}
        if not isinstance(current_form, dict):
            current_form = {}
        default_wordlist_name, _ = self._resolve_hashcat_default_wordlist(normalized_context)
        current_secondary_wordlist = self._optional_text(current_form.get("secondary_wordlist_path"))
        explicit_wordlists = re.findall(r"(?:[A-Za-z]:\\|/)[^\r\n\"']+", text)

        if "ntlm" in lowered:
            hash_mode = 1000
        else:
            hash_text = self._extract_hex_hash(text)
            if not hash_text and sample_hashes:
                first_sample = sample_hashes[0]
                if isinstance(first_sample, dict):
                    hash_text = str(first_sample.get("value") or "")
            if not hash_text and sample_lines:
                hash_text = self._extract_hex_hash("\n".join(str(item) for item in sample_lines[:3]))
            hash_mode = self._guess_hash_mode(hash_text)
            if hash_mode == 0 and hash_text and len(hash_text) != 32:
                warnings.append("当前仅按常见哈希长度做了近似识别，请人工复核 hash_mode。")
            if not hash_text and sample_lines:
                warnings.append("已读取上传的 hash 文件样本，但未从样本中提取到典型十六进制哈希，请人工复核 hash_mode。")

        attack_mode = 0
        if any(keyword in lowered for keyword in ("combinator", "组合模式", "组合字典", "双字典", "两个字典")):
            attack_mode = 1
        elif ("前缀" in lowered or "prefix" in lowered) and (mask_match or "mask" in lowered or "掩码" in lowered):
            attack_mode = 7
        elif any(keyword in lowered for keyword in ("后缀", "suffix", "末尾", "尾部")) and (
            mask_match or "mask" in lowered or "掩码" in lowered
        ):
            attack_mode = 6
        elif mask_match or "掩码" in lowered or "mask" in lowered:
            attack_mode = 3

        explicit_wordlist = explicit_wordlists[0] if explicit_wordlists else path_match.group(0) if path_match else None
        explicit_secondary_wordlist = explicit_wordlists[1] if len(explicit_wordlists) > 1 else None
        current_wordlist = self._optional_text(current_form.get("wordlist_path"))
        wordlist_path = None
        secondary_wordlist_path = None
        if attack_mode in {0, 1, 6, 7}:
            wordlist_path = explicit_wordlist or current_wordlist or default_wordlist_name
        if attack_mode == 1:
            secondary_wordlist_path = explicit_secondary_wordlist or current_secondary_wordlist
        mask = mask_match.group(0) if attack_mode in {3, 6, 7} and mask_match else None

        if attack_mode in {0, 1, 6, 7} and not wordlist_path:
            warnings.append("未识别到字典路径，当前会默认尝试 rockyou.txt，请确认内置字典是否存在。")
        if attack_mode == 1 and not secondary_wordlist_path:
            warnings.append("组合模式需要第二个字典，请补充 secondary_wordlist_path 或上传第二字典。")
        if attack_mode in {3, 6, 7} and not mask:
            warnings.append("未识别到掩码字符串，若使用掩码模式请手动填写 mask。")

        return {
            "hash_mode": hash_mode,
            "attack_mode": attack_mode,
            "wordlist_path": wordlist_path,
            "secondary_wordlist_path": secondary_wordlist_path,
            "mask": mask,
            "session_name": None,
            "extra_args": [],
            "explanation": (
                "已根据输入中的哈希类型关键字、掩码特征、当前表单以及已上传 hash 文件样本给出最可能的 Hashcat 配置。"
            ),
            "confidence": "medium" if warnings else "high",
            "warnings": warnings,
        }

    def _assist_encoding_fallback(self, raw_input: str) -> dict[str, Any]:
        return self._analyze_encoding_input(raw_input)

    def _assist_hash_result_fallback(self, raw_input: str, context: dict[str, Any]) -> dict[str, Any]:
        hash_result = context.get("hash_result")
        warnings: list[str] = []
        findings: list[str] = []
        recommendations: list[str] = []
        confidence = "medium"

        if not isinstance(hash_result, dict):
            return {
                "summary": "当前还没有可供分析的哈希结果。请先上传文件并完成哈希计算，再让我结合结果继续分析。",
                "primary_hash": "SHA256",
                "findings": [],
                "recommendations": [
                    "先生成至少一个强哈希值，建议优先保留 SHA256。",
                    "完成哈希计算后，再结合样本库或情报平台做比对。",
                ],
                "warnings": ["未检测到 hash_result 上下文。"],
                "confidence": "low",
            }

        file_name = str(hash_result.get("file_name") or "当前文件")
        file_size = hash_result.get("file_size")
        algorithms = hash_result.get("algorithms") or []
        hashes = hash_result.get("hashes") or {}
        algorithms_upper = [str(item).upper() for item in algorithms if str(item).strip()]
        primary_hash = next((name for name in ["SHA256", "SHA1", "MD5", "SHA512"] if name in algorithms_upper), "SHA256")
        primary_value = ""
        if isinstance(hashes, dict):
            primary_value = str(hashes.get(primary_hash.lower()) or hashes.get(primary_hash) or "").strip()

        if algorithms_upper:
            findings.append(f"文件“{file_name}”已生成 {len(algorithms_upper)} 种摘要：{'、'.join(algorithms_upper)}。")
        if primary_value:
            findings.append(f"建议以 {primary_hash} 作为主校验值固定证据链，当前值已可直接用于后续比对。")
        if isinstance(file_size, int) and file_size >= 0:
            findings.append(f"当前文件大小为 {file_size} 字节，可与主哈希一起记录为证据留存元数据。")

        lowered = raw_input.lower()
        if "威胁" in raw_input or "情报" in raw_input or "virus" in lowered or "vt" in lowered:
            findings.append("当前更适合先把主哈希送去样本库、威胁情报平台或历史案件库做同源比对。")
        else:
            findings.append("当前更适合作为完整性校验、证据封存和跨平台样本比对的基础索引。")

        recommendations.extend(
            [
                f"在报告中优先记录 {primary_hash}，并保留其他摘要作为兼容性补充。",
                "如需情报排查，可将主哈希与 VirusTotal、内部样本库或历史案件台账交叉检索。",
                "若后续要复核文件是否被篡改，应在拷贝、导出和传输后重复计算并对比同一摘要值。",
            ]
        )

        if not primary_value:
            warnings.append(f"当前未找到 {primary_hash} 的具体值，请检查哈希结果结构。")
            confidence = "low"

        return {
            "summary": f"已结合文件“{file_name}”的当前哈希结果整理用途建议，可直接用于完整性校验和后续样本比对。",
            "primary_hash": primary_hash,
            "findings": findings,
            "recommendations": recommendations,
            "warnings": warnings,
            "confidence": confidence if warnings else "high",
        }

    def _assist_sqlite_result_fallback(self, raw_input: str, context: dict[str, Any]) -> dict[str, Any]:
        browser = context.get("browser")
        selected_table = context.get("selected_table")
        preview = context.get("preview")
        export_result = context.get("table_export")
        full_export = context.get("full_export")

        if not isinstance(browser, dict):
            return {
                "summary": "当前还没有数据库结构上下文。请先上传 SQLite 文件并加载结构，再让我结合表和字段继续分析。",
                "highlighted_tables": [],
                "current_table_name": None,
                "focus_fields": [],
                "schema_notes": [],
                "recommendations": [
                    "先加载数据库结构，确认有哪些表和字段。",
                    "优先预览行数较多或表名带有 user、message、history、event 等关键词的表。",
                ],
                "warnings": ["未检测到 sqlite browser 上下文。"],
            }

        tables_raw = browser.get("tables") or []
        tables = [item for item in tables_raw if isinstance(item, dict)]
        database_name = str(browser.get("database_name") or "当前数据库")

        def table_priority(item: dict[str, Any]) -> tuple[int, int]:
            table_name = str(item.get("table_name") or "").lower()
            row_count = int(item.get("row_count") or 0)
            score = 0
            keywords = {
                "message": 5,
                "chat": 5,
                "login": 5,
                "account": 4,
                "user": 4,
                "history": 4,
                "event": 4,
                "record": 3,
                "session": 3,
                "cache": 2,
                "file": 2,
                "attach": 2,
            }
            for keyword, weight in keywords.items():
                if keyword in table_name:
                    score += weight
            return score, row_count

        ranked_tables = sorted(tables, key=table_priority, reverse=True)
        highlighted_tables: list[dict[str, Any]] = []
        for item in ranked_tables[:4]:
            score, row_count = table_priority(item)
            priority = "high" if score >= 5 else "medium" if score >= 2 else "low"
            reason_parts = []
            if score >= 5:
                reason_parts.append("表名含有高价值行为线索关键词")
            elif score >= 2:
                reason_parts.append("表名包含常见取证关注关键词")
            if row_count:
                reason_parts.append(f"当前记录数约 {row_count}")
            highlighted_tables.append(
                {
                    "table_name": str(item.get("table_name") or "未命名表"),
                    "priority": priority,
                    "reason": "，".join(reason_parts) or "可作为常规优先检查对象。",
                }
            )

        focus_fields: list[str] = []
        schema_notes: list[str] = []
        current_table_name: str | None = None
        if isinstance(selected_table, dict):
            current_table_name = self._optional_text(selected_table.get("table_name"))
            columns = selected_table.get("columns") or []
            if isinstance(columns, list):
                for column in columns:
                    if not isinstance(column, dict):
                        continue
                    column_name = str(column.get("name") or "")
                    lowered_name = column_name.lower()
                    if any(
                        token in lowered_name
                        for token in ["id", "user", "name", "email", "phone", "time", "date", "path", "file", "message", "ip", "content"]
                    ):
                        focus_fields.append(column_name)
                    if column.get("is_primary_key"):
                        schema_notes.append(f"字段 {column_name} 为主键，可用于记录去重和关联。")
                    if str(column.get("type") or "").upper() in {"BLOB", "JSON"}:
                        schema_notes.append(f"字段 {column_name} 类型为 {column.get('type')}，建议单独抽样检查内容。")
            schema_sql = self._optional_text(selected_table.get("schema_sql"))
            if schema_sql:
                schema_notes.append("当前表已提供建表 SQL，可结合约束和索引判断字段关系。")

        if isinstance(preview, dict):
            returned_rows = int(preview.get("returned_rows") or 0)
            total_rows = int(preview.get("total_rows") or 0)
            schema_notes.append(f"当前预览返回 {returned_rows} 行，总匹配行数约 {total_rows}。")

        if isinstance(export_result, dict):
            schema_notes.append(f"当前表已导出为 {export_result.get('csv_name') or 'CSV'}，可直接做离线筛选。")
        if isinstance(full_export, dict):
            schema_notes.append(f"整库导出包 {full_export.get('zip_name') or 'ZIP'} 已可下载。")

        if not focus_fields and isinstance(selected_table, dict):
            columns = selected_table.get("columns") or []
            if isinstance(columns, list):
                focus_fields = [str(column.get("name") or "") for column in columns[:5] if isinstance(column, dict)]

        recommendations = [
            "优先查看高优先级表，再按时间、账号、路径、消息内容等字段做过滤。",
            "若当前表记录较多，建议先限制返回行数并按关键字段逐步缩小范围。",
            "对确认有价值的表可先导出当前筛选结果，再做外部关联分析和证据留存。",
        ]
        if "结构" in raw_input or "schema" in raw_input.lower():
            recommendations.insert(0, "先结合建表 SQL、主键和字段类型理解表关系，再决定导出策略。")

        return {
            "summary": f"已结合数据库“{database_name}”的当前结构和预览结果整理排查建议，适合先做表级优先级筛查再深入字段分析。",
            "highlighted_tables": highlighted_tables,
            "current_table_name": current_table_name,
            "focus_fields": list(dict.fromkeys([item for item in focus_fields if item])),
            "schema_notes": list(dict.fromkeys(schema_notes)),
            "recommendations": recommendations,
            "warnings": [],
        }

    def _guess_timestamp_type_from_value(self, timestamp: str) -> str:
        integer_part = timestamp.split(".")[0].lstrip("+-")
        if not integer_part:
            return "unix"
        length = len(integer_part)
        if length in {10, 13, 16, 19}:
            return "unix"
        if length >= 18:
            return "dotnet_ticks"
        if length >= 16:
            return "windows_filetime"
        return "unix"

    def _extract_hex_hash(self, text: str) -> str:
        match = re.search(r"\b[a-fA-F0-9]{32,128}\b", text)
        return match.group(0) if match else ""

    def _guess_hash_mode(self, hash_text: str) -> int:
        length = len(hash_text)
        if length == 32:
            return 0
        if length == 40:
            return 100
        if length == 64:
            return 1400
        if length == 128:
            return 1700
        return 0

    def _score_to_confidence(self, score: int) -> str:
        if score >= 80:
            return "high"
        if score >= 55:
            return "medium"
        return "low"

    def _analyze_with_local_fallback(self, parsed_result: ParsedLogResponse, question: str) -> AIAnalysisResult:
        findings: list[FindingItem] = []
        timeline_summary: list[str] = []
        recommendations: list[str] = []

        if parsed_result.has_timestamp:
            timeline_summary.append("日志中检测到时间戳，可结合时间维度进一步复原事件顺序。")
        else:
            timeline_summary.append("日志中未明显检测到标准时间戳，时间线复原能力受限。")

        timeline_summary.append(f"本次共解析 {parsed_result.total_lines} 行日志。")
        timeline_summary.append(f"基础解析策略来源：{parsed_result.parse_strategy.source}。")

        if parsed_result.level_counts.error > 0:
            findings.append(
                FindingItem(
                    title="检测到错误级别日志",
                    evidence=[f"error 相关行数：{parsed_result.level_counts.error}", *self._pick_evidence(parsed_result)],
                    explanation="日志中存在错误或异常关键字，说明至少有部分执行过程失败，但具体影响范围仍需结合完整上下文确认。",
                )
            )

        if parsed_result.level_counts.warning > 0:
            findings.append(
                FindingItem(
                    title="检测到告警级别日志",
                    evidence=[f"warning 相关行数：{parsed_result.level_counts.warning}"],
                    explanation="告警信息可能指向配置偏差、资源紧张或异常前兆，但不必然意味着安全事件已经成立。",
                )
            )

        if parsed_result.possible_ips:
            findings.append(
                FindingItem(
                    title="日志中存在网络地址线索",
                    evidence=[f"提取到的 IP：{', '.join(parsed_result.possible_ips[:5])}"],
                    explanation="可将这些 IP 与主机资产、时间点和访问动作交叉比对，辅助判断是否存在可疑连接或横向行为。",
                )
            )

        if not findings:
            findings.append(
                FindingItem(
                    title="当前证据有限",
                    evidence=["未检测到明显的 error、warning 或高风险异常片段。"],
                    explanation="现有结构化结果没有直接指向高风险事件，但这并不等于绝对安全，仍应人工复核原始日志语义。",
                )
            )

        risk_level = self._estimate_risk_level(parsed_result)
        recommendations.extend(
            [
                "优先复核关键异常片段对应的完整上下文，确认失败原因、影响范围和是否涉及敏感资产。",
                "将提取出的 IP、时间点、账号名和主机名做交叉关联，补充证据链。",
                "如果日志格式较特殊，建议继续补充样本行并优化 AI 解析策略关键字。",
            ]
        )

        summary = (
            f"围绕问题“{question}”进行了规则化研判。"
            f"日志共 {parsed_result.total_lines} 行，"
            f"error 相关 {parsed_result.level_counts.error} 行，"
            f"warning 相关 {parsed_result.level_counts.warning} 行。"
            "当前结论来自本地回退分析，适合作为初步筛查结果。"
        )

        return AIAnalysisResult(
            summary=summary,
            risk_level=risk_level,
            findings=findings,
            timeline_summary=timeline_summary,
            recommendations=recommendations,
        )

    def _pick_evidence(self, parsed_result: ParsedLogResponse) -> list[str]:
        evidence: list[str] = []
        seen: set[str] = set()
        for fragment in parsed_result.key_fragments[:2]:
            for line in fragment.snippet[:2]:
                if line in seen:
                    continue
                seen.add(line)
                evidence.append(line)
                if len(evidence) >= 4:
                    return evidence
        return evidence

    def _estimate_risk_level(self, parsed_result: ParsedLogResponse) -> str:
        if parsed_result.level_counts.error >= 10 or len(parsed_result.key_fragments) >= 5:
            return "high"
        if parsed_result.level_counts.error > 0 or parsed_result.level_counts.warning >= 5:
            return "medium"
        return "low"


ai_analysis_service = AIAnalysisService()
