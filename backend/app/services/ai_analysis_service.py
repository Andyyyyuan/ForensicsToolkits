import base64
import binascii
import html
import json
import os
import quopri
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
    "Base45",
    "Base58",
    "Base62",
    "Base64",
    "Base85",
    "Base32",
    "Hex",
    "Binary",
    "Octal",
    "Quoted Printable",
    "Morse Code",
    "ROT13",
    "URL",
    "Unicode Escape",
    "HTML Entity",
    "JSON Escape",
    "Unknown",
]
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
MORSE_CODE_TABLE = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    ".-.-.-": ".",
    "--..--": ",",
    "..--..": "?",
    "-.-.--": "!",
    "-..-.": "/",
    ".--.-.": "@",
    "-...-": "=",
    "---...": ":",
    "-....-": "-",
    "-.--.": "(",
    "-.--.-": ")",
    ".----.": "'",
    ".-..-.": '"',
    ".-.-.": "+",
}
SYSTEM_RESPONSE_STYLE = (
    "必须用中文回答。"
    "不要使用生硬的通用称呼。"
    "如需称呼，请使用“同学你好”。"
    "结论要和证据对应，证据不足时明确说明不足点。"
    "表达要简洁、专业、克制、可执行，不要写空泛套话。"
)
TOOL_KNOWLEDGE_STYLE = (
    "如果用户的问题明显是在询问本工具相关的概念、原理、用途、区别、排错思路或最佳实践，"
    "即使当前缺少具体文件、哈希、表结构、日志片段或样本，也要先直接回答该知识问题。"
    "此时要明确哪些内容属于通用知识，哪些内容尚未结合当前案件样本验证。"
    "不要因为缺少上下文，就机械地只回复“未提供文件/哈希/数据库/样本”。"
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
            user_payload=self._build_timestamp_ai_payload(raw_input),
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
            normalizer=lambda payload: self._normalize_hashcat_assist_payload(payload, raw_input=raw_input),
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
            normalizer=lambda payload: self._normalize_hash_result_assist_payload(payload, raw_input=raw_input),
            fallback_factory=lambda error: self._fallback_stream_payload(
                self._assist_hash_result_fallback(raw_input, normalized_context),
                error,
            ),
            system_prompt=self._hash_result_assist_prompt(),
            user_payload=self._build_hash_result_ai_payload(raw_input, normalized_context),
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
            user_payload=self._build_sqlite_ai_payload(raw_input, normalized_context),
        ):
            yield event

    def _log_analysis_prompt(self) -> str:
        return (
            "你是一名电子取证日志研判助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            f"{TOOL_KNOWLEDGE_STYLE}"
            "输入里会额外提供 query_intent。若 query_intent.type=knowledge_question，必须把 question 当作概念提问来回答，"
            "先解释概念，再引用当前日志统计或片段作为补充背景，不要把概念问题误写成案件定性结论。"
            "同学你好，请只依据提供的结构化基础解析结果、关键片段和提问进行判断。"
            "禁止编造不存在的事实；证据不足时必须明确说明。"
            "严格输出 JSON，字段必须包含：summary、risk_level、findings、timeline_summary、recommendations。"
            "findings 中的每条结论都必须能对应到输入里的证据。"
        )

    def _timestamp_assist_prompt(self) -> str:
        return (
            "你是一名电子取证时间戳识别助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            f"{TOOL_KNOWLEDGE_STYLE}"
            "输入里会额外提供 query_intent。若 query_intent.type=knowledge_question，必须把 user_input 当概念问题处理，"
            "不要把整句问题当待解析时间戳样本；此时 explanation 要直接回答问题，timestamp 可留空，timestamp_type 选择最相关类型。"
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
            f"{TOOL_KNOWLEDGE_STYLE}"
            "输入里会额外提供 query_intent。若 query_intent.type=knowledge_question，必须先回答 Hashcat 相关概念或最佳实践，"
            "不要机械地因为缺少 hash 样本就只回复缺少上下文；配置字段可给出最相关的通用示例，并在 warnings 说明未结合当前样本验证。"
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
            f"{TOOL_KNOWLEDGE_STYLE}"
            "输入里会额外提供 query_intent。若 query_intent.type=knowledge_question，必须把 user_input 当概念提问，"
            "不要因为整句问题本身是普通可读文本，就机械地把 recommended_encoding 判成 UTF-8；应优先返回用户正在询问的编码主题。"
            "同学你好，请优先按 CTF 和取证竞赛里常见的编码、转义或数据表示形式做判断，再给出 CyberChef 可尝试的配方。"
            "只输出 JSON，字段必须包含：recommended_encoding、candidates、suggested_recipe、cyberchef_recipe、cyberchef_input、explanation、warnings。"
            "candidates 必须是数组，每项字段包含：name、confidence、score、reason。"
            f"name 应优先从以下候选中选择：{', '.join(SUPPORTED_ENCODING_NAMES)}。"
            "score 为 0 到 100 的整数。"
            "优先考虑 Base45、Base58、Base62、Base64、Base85、Base32、Hex、Binary、Octal、Quoted Printable、Morse Code、ROT13、URL 以及常见转义序列。"
            "除非用户明确在排查乱码或字符集问题，不要把 UTF-8、GBK、GB18030、UTF-16 这类字符集当成主候选。"
            "必须区分 Base32 与 Base64：Base32 常见字符集主要是 A-Z、2-7 和 =，通常不会出现 +、/；Base64 常见字符集是 A-Z、a-z、0-9、+、/ 和 =。"
            "如果一层解码后仍明显像另一层编码，suggested_recipe 必须按解码顺序输出数组，并优先尝试 2 到 3 层嵌套，例如 ['From Base64', 'From Base64']、['From Base58', 'From Hex'] 或 ['From Base64', 'From Base64', 'From Hex']。"
            "只有证据充分时才给出多层判断；若 Base32 与 Base64 或 Base58 与 Base62 存在歧义，必须在 warnings 中说明。"
            "cyberchef_recipe 必须是可直接放入 CyberChef URL recipe 参数的配方字符串。"
            "cyberchef_input 必须保持原始输入，不要自行做 Base64 编码。"
            "不要虚构已经成功解码出的最终明文，只能给出识别判断、分层依据和建议配方。"
        )

    def _hash_result_assist_prompt(self) -> str:
        return (
            "你是一名电子取证哈希分析助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            f"{TOOL_KNOWLEDGE_STYLE}"
            "输入里会额外提供 query_intent。若 query_intent.type=knowledge_question，必须优先回答哈希概念、用途、区别或最佳实践，"
            "即使当前没有 hash_result 上下文，也不要只机械要求先上传文件。"
            "同学你好，请结合提问、文件哈希结果和可用元数据，给出可直接执行的取证比对建议。"
            "不要编造未提供的文件来源、恶意结论或情报检索命中结果。"
            "只输出 JSON，字段必须包含：summary、primary_hash、findings、recommendations、warnings、confidence。"
            "findings 必须是字符串数组，每条都要简洁、具体、可执行。"
        )

    def _sqlite_assist_prompt(self) -> str:
        return (
            "你是一名电子取证 SQLite 分析助手。"
            f"{SYSTEM_RESPONSE_STYLE}"
            f"{TOOL_KNOWLEDGE_STYLE}"
            "输入里会额外提供 query_intent。若 query_intent.type=knowledge_question，必须先回答 SQLite 相关概念、结构理解或取证思路，"
            "不要机械地因为缺少数据库结构就只回复先上传数据库。"
            "同学你好，请结合提问、当前数据库表结构、选中表和预览数据，指出优先检查的表、字段和导出方向。"
            "禁止编造数据库中不存在的字段、关系或行内容，只能依据提供的上下文推断。"
            "只输出 JSON，字段必须包含：summary、highlighted_tables、current_table_name、focus_fields、schema_notes、recommendations、warnings。"
            "highlighted_tables 为数组，每项字段必须包含：table_name、priority、reason。priority 只能是 high、medium、low。"
            "优先说明为什么当前表或字段值得关注，而不是泛泛而谈。"
        )

    def _build_encoding_ai_payload(self, raw_input: str) -> dict[str, Any]:
        knowledge_question = self._is_knowledge_question(raw_input)
        payload = {
            "user_input": raw_input,
            "query_intent": self._build_query_intent(
                "encoding_converter",
                raw_input,
                has_context=not knowledge_question,
            ),
            "output_requirement": (
                "输出必须是 JSON，所有说明必须使用中文。"
                "识别时优先覆盖 CTF 和取证竞赛常见编码。"
                "如果判断为多层编码，suggested_recipe 必须按解码顺序给出 2 到 3 个步骤。"
                "若 query_intent.type=knowledge_question，必须把问题当概念提问，不要把整句问题按普通文本样本识别为 UTF-8。"
                "若没有命中明显字符集乱码特征，不要默认推荐 UTF-8、GBK、GB18030 或 UTF-16。"
            ),
        }
        if knowledge_question:
            payload["knowledge_context"] = {
                "mentioned_topics": self._extract_encoding_topics(raw_input) or [self._detect_encoding_topic(raw_input)],
                "instruction": "当前输入是提问，不是待识别样本。请围绕被提到的编码概念作答。",
            }
            return payload

        analysis = self._analyze_encoding_input(raw_input)
        payload["encoding_context"] = analysis["evidence"]
        payload["suggested_recipe_hint"] = analysis["suggested_recipe"]
        return payload

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
            user_payload=self._build_timestamp_ai_payload(raw_input),
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
        return self._normalize_hashcat_assist_payload(self._parse_json_content(content), raw_input=raw_input), reasoning

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
            user_payload=self._build_hash_result_ai_payload(raw_input, context),
        )
        return self._normalize_hash_result_assist_payload(self._parse_json_content(content), raw_input=raw_input), reasoning

    async def _assist_sqlite_result_with_model(
        self,
        raw_input: str,
        context: dict[str, Any],
        mode: str,
    ) -> tuple[dict[str, Any], str]:
        content, reasoning = await self._request_json_completion(
            model=self.get_model_name(mode),
            system_prompt=self._sqlite_assist_prompt(),
            user_payload=self._build_sqlite_ai_payload(raw_input, context),
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
            "query_intent": self._build_query_intent(
                "log_parser",
                question,
                has_context=parsed_result.total_lines > 0,
            ),
            "context_summary": {
                "total_lines": parsed_result.total_lines,
                "error_count": parsed_result.level_counts.error,
                "warning_count": parsed_result.level_counts.warning,
                "has_timestamp": parsed_result.has_timestamp,
            },
            "parsed_result": parsed_result.model_dump(),
            "evidence_constraints": [
                "仅依据输入证据做结论",
                "证据不足时明确写出不足之处",
                "所有 findings 都应包含 evidence",
                "若 query_intent.type=knowledge_question，先直接回答概念，再引用当前日志作为补充背景。",
            ],
        }

    def _build_query_intent(self, tool_id: str, text: str, *, has_context: bool) -> dict[str, Any]:
        detector_map: dict[str, Callable[[str], str]] = {
            "log_parser": self._detect_log_topic,
            "timestamp_parser": self._detect_timestamp_topic,
            "hashcat_gui": self._detect_hashcat_topic,
            "encoding_converter": self._detect_encoding_topic,
            "hash_tool": self._detect_hash_topic,
            "sqlite2csv": self._detect_sqlite_topic,
        }
        detector = detector_map.get(tool_id)
        knowledge_question = self._is_knowledge_question(text)
        topic = detector(text) if detector else "generic"
        return {
            "type": "knowledge_question" if knowledge_question else "analysis_request",
            "topic": topic,
            "has_context": has_context,
            "treat_input_as": "question" if knowledge_question else "task_request",
            "instruction": (
                "先回答用户正在问的概念、用途、区别或最佳实践，再明确哪些内容尚未结合当前样本验证。"
                if knowledge_question
                else "结合当前上下文输出结构化分析或配置结果。"
            ),
        }

    def _build_timestamp_ai_payload(self, raw_input: str) -> dict[str, Any]:
        number_candidates = re.findall(r"[-+]?\d+(?:\.\d+)?", raw_input)
        return {
            "user_input": raw_input,
            "query_intent": self._build_query_intent(
                "timestamp_parser",
                raw_input,
                has_context=bool(number_candidates),
            ),
            "timestamp_context": {
                "detected_numbers": number_candidates[:3],
                "topic_hint": self._detect_timestamp_topic(raw_input),
            },
            "output_requirement": (
                "输出必须是 JSON，explanation 和 warnings 必须使用中文。"
                "若 query_intent.type=knowledge_question 且没有明确时间戳数值，timestamp 可留空，重点在 explanation 中直接回答概念。"
            ),
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
        current_form = normalized_context.get("current_form") if isinstance(normalized_context, dict) else {}
        if not isinstance(current_form, dict):
            current_form = {}

        runtime_context.setdefault("default_wordlist_name", default_wordlist_name)
        if default_wordlist_path:
            runtime_context.setdefault("default_wordlist_path", default_wordlist_path)

        has_form_context = any(
            self._optional_text(current_form.get(key))
            for key in ("wordlist_path", "secondary_wordlist_path", "mask", "session_name")
        ) or any(
            isinstance(current_form.get(key), int)
            for key in ("hash_mode", "attack_mode")
        )
        has_file_context = bool(hash_file_context and (hash_file_context.get("sample_lines") or hash_file_context.get("sample_hashes")))

        return {
            "user_input": raw_input,
            "query_intent": self._build_query_intent(
                "hashcat_gui",
                raw_input,
                has_context=has_form_context or has_file_context,
            ),
            "hashcat_context": {
                **normalized_context,
                "runtime": runtime_context,
                "hash_file": hash_file_context,
            },
            "knowledge_context": {
                "topic_hint": self._detect_hashcat_topic(raw_input),
                "default_wordlist_name": default_wordlist_name,
            },
            "output_requirement": (
                "输出必须是 JSON，explanation 和 warnings 必须使用中文。"
                "若无更强线索则默认使用 attack_mode=0，并把 wordlist_path 填为 rockyou.txt。"
                "attack_mode=1 时需要 secondary_wordlist_path。"
                "attack_mode=3 时只保留 mask。"
                "attack_mode=6 为字典加后缀掩码。"
                "attack_mode=7 为前缀掩码加字典。"
                "若 query_intent.type=knowledge_question，必须先直接回答概念问题，不要机械要求补样本。"
            ),
        }

    def _build_hash_result_ai_payload(self, raw_input: str, context: dict[str, Any]) -> dict[str, Any]:
        hash_result = context.get("hash_result") if isinstance(context, dict) else None
        algorithms = hash_result.get("algorithms") if isinstance(hash_result, dict) else []
        file_name = str(hash_result.get("file_name") or "") if isinstance(hash_result, dict) else ""
        return {
            "user_input": raw_input,
            "query_intent": self._build_query_intent(
                "hash_tool",
                raw_input,
                has_context=isinstance(hash_result, dict),
            ),
            "hash_context": context,
            "context_summary": {
                "has_hash_result": isinstance(hash_result, dict),
                "file_name": file_name or None,
                "algorithms": algorithms if isinstance(algorithms, list) else [],
            },
            "output_requirement": (
                "输出必须是 JSON，所有说明必须使用中文。"
                "若 query_intent.type=knowledge_question，先直接回答概念、用途或区别，再说明当前上下文是否已验证。"
            ),
        }

    def _build_sqlite_ai_payload(self, raw_input: str, context: dict[str, Any]) -> dict[str, Any]:
        browser = context.get("browser") if isinstance(context, dict) else None
        tables = browser.get("tables") if isinstance(browser, dict) else []
        database_name = str(browser.get("database_name") or "") if isinstance(browser, dict) else ""
        return {
            "user_input": raw_input,
            "query_intent": self._build_query_intent(
                "sqlite2csv",
                raw_input,
                has_context=isinstance(browser, dict),
            ),
            "sqlite_context": context,
            "context_summary": {
                "has_browser_context": isinstance(browser, dict),
                "database_name": database_name or None,
                "table_count": len(tables) if isinstance(tables, list) else 0,
            },
            "output_requirement": (
                "输出必须是 JSON，所有说明必须使用中文。"
                "若 query_intent.type=knowledge_question，先直接回答 SQLite 结构或取证概念，再补充当前数据库上下文。"
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

    def _normalize_hashcat_assist_payload(self, payload: dict[str, Any], raw_input: str | None = None) -> dict[str, Any]:
        attack_mode = payload.get("attack_mode", 0)
        try:
            attack_mode_value = int(attack_mode)
        except (TypeError, ValueError):
            attack_mode_value = 0
        if attack_mode_value not in {0, 1, 3, 6, 7}:
            attack_mode_value = 0

        question_text = raw_input or ""
        if self._is_knowledge_question(question_text):
            topic = self._detect_hashcat_topic(question_text)
            if topic == "attack_mode_1":
                attack_mode_value = 1
            elif topic == "mask_mode":
                attack_mode_value = 3

            lowered_question = question_text.lower()
            if ("前缀" in question_text or "prefix" in lowered_question) and ("mask" in lowered_question or "掩码" in question_text):
                attack_mode_value = 7
            elif any(keyword in lowered_question for keyword in ("后缀", "suffix", "末尾", "尾部")) and (
                "mask" in lowered_question or "掩码" in question_text
            ):
                attack_mode_value = 6

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
        source_input = raw_input or self._optional_text(payload.get("cyberchef_input") or payload.get("input")) or ""
        local_analysis = self._analyze_encoding_input(source_input)
        knowledge_fallback = self._build_encoding_knowledge_fallback(raw_input) if raw_input and self._is_knowledge_question(raw_input) else None
        allowed_encodings = set(SUPPORTED_ENCODING_NAMES) | {"UTF-8", "GBK", "GB18030", "UTF-16", "UTF-16LE", "UTF-16BE"}
        local_primary = local_analysis["candidates"][0] if local_analysis.get("candidates") else {"name": local_analysis["recommended_encoding"], "score": 0}
        local_primary_name = str(local_primary.get("name") or local_analysis["recommended_encoding"])
        try:
            local_primary_score = int(local_primary.get("score") or 0)
        except (TypeError, ValueError):
            local_primary_score = 0

        recommended_encoding = (
            str(payload.get("recommended_encoding") or payload.get("encoding") or local_analysis["recommended_encoding"]).strip()
            or local_analysis["recommended_encoding"]
        )
        model_recommended_encoding = recommended_encoding
        if recommended_encoding not in allowed_encodings:
            recommended_encoding = knowledge_fallback["recommended_encoding"] if knowledge_fallback else local_analysis["recommended_encoding"]
        elif knowledge_fallback and knowledge_fallback["recommended_encoding"] != "Unknown":
            recommended_encoding = knowledge_fallback["recommended_encoding"]
        elif local_primary_name != "Unknown" and local_primary_score >= 75 and recommended_encoding != local_primary_name:
            recommended_encoding = local_primary_name

        recipe_field = payload.get("recipe")
        suggested_recipe_source = payload.get("suggested_recipe")
        if suggested_recipe_source is None and not self._looks_like_cyberchef_recipe(recipe_field):
            suggested_recipe_source = recipe_field
        suggested_recipe = self._coerce_recipe_steps(suggested_recipe_source)
        recipe_overridden_by_local = False

        local_recipe = list(local_analysis["suggested_recipe"])
        if knowledge_fallback:
            knowledge_recipe = list(knowledge_fallback.get("suggested_recipe") or [])
            if not suggested_recipe or suggested_recipe == ["Decode text"] or all(step.lower() == "decode text" for step in suggested_recipe):
                suggested_recipe = knowledge_recipe
        if recommended_encoding == local_primary_name and local_primary_score >= 75:
            if not suggested_recipe or len(local_recipe) > len(suggested_recipe):
                suggested_recipe = local_recipe
                recipe_overridden_by_local = True
            elif local_recipe and suggested_recipe and suggested_recipe[0].strip().lower() != local_recipe[0].strip().lower():
                suggested_recipe = local_recipe
                recipe_overridden_by_local = True
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
        if knowledge_fallback and recommended_encoding == knowledge_fallback["recommended_encoding"]:
            candidates = list(knowledge_fallback["candidates"]) + candidates
        elif recommended_encoding == local_primary_name and local_primary_score >= 75:
            candidates = list(local_analysis["candidates"]) + candidates
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

        explanation = str(payload.get("explanation") or local_analysis["explanation"] or "已根据当前输入给出最可能的编码判断和 CyberChef 建议。")
        if knowledge_fallback:
            if len(explanation.strip()) < 30 or not re.search(r"(是一种|用于|字符集|表示方式|常见|本质上)", explanation):
                explanation = str(knowledge_fallback["explanation"])
        elif recipe_overridden_by_local:
            explanation = str(local_analysis["explanation"])
        elif recommended_encoding == local_primary_name and local_primary_score >= 75 and model_recommended_encoding != recommended_encoding:
            explanation = str(local_analysis["explanation"])

        return {
            "recommended_encoding": recommended_encoding,
            "candidates": candidates,
            "suggested_recipe": suggested_recipe,
            "cyberchef_recipe": cyberchef_recipe,
            "cyberchef_input": cyberchef_input,
            "explanation": explanation,
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
        return steps

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
            return "".join(recipe_parts)

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
            "base45": f"From_Base45('{BASE45_ALPHABET}',true)",
            "from base45": f"From_Base45('{BASE45_ALPHABET}',true)",
            "base58": f"From_Base58('{BASE58_ALPHABET}',true)",
            "from base58": f"From_Base58('{BASE58_ALPHABET}',true)",
            "base62": f"From_Base62('{BASE62_ALPHABET}')",
            "from base62": f"From_Base62('{BASE62_ALPHABET}')",
            "hex": "From_Hex('Auto')",
            "from hex": "From_Hex('Auto')",
            "base64": "From_Base64('A-Za-z0-9+/=',true,false)",
            "from base64": "From_Base64('A-Za-z0-9+/=',true,false)",
            "base85": "From_Base85('!-u',true,'z')",
            "from base85": "From_Base85('!-u',true,'z')",
            "base32": "From_Base32('A-Z2-7=',false)",
            "from base32": "From_Base32('A-Z2-7=',false)",
            "binary": "From_Binary('Space',8)",
            "from binary": "From_Binary('Space',8)",
            "octal": "From_Octal('Space')",
            "from octal": "From_Octal('Space')",
            "quoted printable": "From_Quoted_Printable()",
            "from quoted printable": "From_Quoted_Printable()",
            "qp": "From_Quoted_Printable()",
            "morse": "From_Morse_Code('Space','Forward slash')",
            "morse code": "From_Morse_Code('Space','Forward slash')",
            "moss": "From_Morse_Code('Space','Forward slash')",
            "rot13": "ROT13(true,true,false,13)",
            "url": "URL_Decode()",
            "url decode": "URL_Decode()",
            "unicode escape": "Unescape_Unicode_Characters()",
            "unescape unicode characters": "Unescape_Unicode_Characters()",
            "html entity": "From_HTML_Entity()",
            "from html entity": "From_HTML_Entity()",
            "json escape": "Unescape_Unicode_Characters()",
        }
        return suggested_map.get(normalized)

    def _encoding_to_cyberchef_decode_recipe(self, recommended_encoding: str) -> str | None:
        normalized = recommended_encoding.strip().lower()
        encoding_map = {
            "base45": f"From_Base45('{BASE45_ALPHABET}',true)",
            "base58": f"From_Base58('{BASE58_ALPHABET}',true)",
            "base62": f"From_Base62('{BASE62_ALPHABET}')",
            "utf-8": "Decode_text('UTF-8 (65001)')",
            "utf8": "Decode_text('UTF-8 (65001)')",
            "gbk": "Decode_text('GBK (936)')",
            "gb18030": "Decode_text('GB18030 (54936)')",
            "utf-16": "Decode_text('UTF-16LE (1200)')",
            "utf-16le": "Decode_text('UTF-16LE (1200)')",
            "utf-16be": "Decode_text('UTF-16BE (1201)')",
            "base64": "From_Base64('A-Za-z0-9+/=',true,false)",
            "base85": "From_Base85('!-u',true,'z')",
            "base32": "From_Base32('A-Z2-7=',false)",
            "hex": "From_Hex('Auto')",
            "binary": "From_Binary('Space',8)",
            "octal": "From_Octal('Space')",
            "quoted printable": "From_Quoted_Printable()",
            "morse code": "From_Morse_Code('Space','Forward slash')",
            "rot13": "ROT13(true,true,false,13)",
            "url": "URL_Decode()",
            "unicode escape": "Unescape_Unicode_Characters()",
            "html entity": "From_HTML_Entity()",
            "json escape": "Unescape_Unicode_Characters()",
        }
        return encoding_map.get(normalized)

    def _analyze_encoding_input(self, raw_input: str) -> dict[str, Any]:
        text = raw_input.strip()
        if not text:
            return {
                "recommended_encoding": "Unknown",
                "candidates": [
                    {
                        "name": "Unknown",
                        "score": 20,
                        "confidence": "low",
                        "reason": "输入为空，无法判断具体编码类型。",
                    }
                ],
                "suggested_recipe": [],
                "cyberchef_recipe": None,
                "cyberchef_input": "",
                "explanation": "未收到待分析样本，因此无法生成编码识别结果。",
                "warnings": ["输入为空，请提供待识别样本。"],
                "evidence": {
                    "trimmed_length": 0,
                    "compact_length": 0,
                    "contains_whitespace": False,
                    "probe_summary": {},
                    "decoded_layers": [],
                    "candidate_summary": [],
                },
            }

        compact = re.sub(r"\s+", "", text)
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

        probe_map = {
            "Base45": self._probe_base45_text(text),
            "Base58": self._probe_base58_text(text),
            "Base62": self._probe_base62_text(text),
            "Base64": self._probe_base64_text(text),
            "Base85": self._probe_base85_text(text),
            "Base32": self._probe_base32_text(text),
            "Hex": self._probe_hex_text(text),
            "Binary": self._probe_binary_text(text),
            "Octal": self._probe_octal_text(text),
            "Quoted Printable": self._probe_quoted_printable_text(text),
            "Morse Code": self._probe_morse_text(text),
            "ROT13": self._probe_rot13_text(text),
            "URL": self._probe_url_text(text),
            "Unicode Escape": self._probe_unicode_escape_text(text),
            "HTML Entity": self._probe_html_entity_text(text),
            "JSON Escape": self._probe_json_escape_text(text),
        }

        for name in (
            "Base45",
            "Base58",
            "Base62",
            "Base64",
            "Base85",
            "Base32",
            "Hex",
            "Binary",
            "Octal",
            "Quoted Printable",
            "Morse Code",
            "ROT13",
            "URL",
            "Unicode Escape",
            "HTML Entity",
            "JSON Escape",
        ):
            probe = probe_map[name]
            if int(probe["score"]) > 0:
                add_candidate(name, int(probe["score"]), str(probe["reason"]))

        if not candidates:
            add_candidate("Unknown", 42, "未命中常见 CTF/取证编码特征，当前更像普通文本、明文问题或需要结合上下文继续判断。")

        if any(token in text for token in ["Ã", "ä", "å", "æ", "ï", "�"]):
            warnings.append("当前文本同时带有乱码特征；如果原始来源涉及字符集误解码，请额外按 UTF-8/GBK/GB18030/UTF-16 方向人工复核。")

        candidates = self._dedupe_encoding_candidates(candidates)
        recipe_steps, decoded_layers = self._discover_encoding_recipe(text, max_depth=3)

        base64_probe = probe_map["Base64"]
        base32_probe = probe_map["Base32"]
        base58_probe = probe_map["Base58"]
        base62_probe = probe_map["Base62"]
        if base64_probe["score"] >= 78 and base32_probe["score"] >= 78 and abs(base64_probe["score"] - base32_probe["score"]) <= 10:
            warnings.append("当前同时命中 Base32 和 Base64 特征，请优先结合字符集差异与试解码结果人工复核。")
        if base58_probe["score"] >= 70 and base62_probe["score"] >= 70 and abs(base58_probe["score"] - base62_probe["score"]) <= 8:
            warnings.append("当前同时命中 Base58 与 Base62 特征，两者字母表不同但都可能成立，请结合字符集和试解码结果人工复核。")

        if not recipe_steps:
            recommended_name = candidates[0]["name"] if candidates else "Unknown"
            fallback_step = self._encoding_step_name(recommended_name)
            if fallback_step:
                recipe_steps = [fallback_step]
        recommended = candidates[0]["name"] if candidates else "Unknown"
        if len(recipe_steps) >= 2:
            explanation = (
                "检测到更像 2 到 3 层嵌套编码包装，已按字符集、分隔符和试解码结果给出分层 CyberChef 配方。"
            )
        elif recommended in {
            "Base45",
            "Base58",
            "Base62",
            "Base64",
            "Base85",
            "Base32",
            "Hex",
            "Binary",
            "Octal",
            "Quoted Printable",
            "Morse Code",
            "ROT13",
            "URL",
            "Unicode Escape",
            "HTML Entity",
            "JSON Escape",
        }:
            explanation = "已根据字符集、分隔符、padding、转义模式和试解码结果给出最可能的编码判断。"
        else:
            explanation = "未命中明显的 CTF/取证常见编码特征，当前更像普通文本或需要结合题目上下文继续判断。"

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
                "probe_summary": {
                    name: {key: value for key, value in probe.items() if key in {"score", "reason", "preview"} and value}
                    for name, probe in probe_map.items()
                    if int(probe["score"]) > 0
                },
                "decoded_layers": decoded_layers,
                "candidate_summary": candidates[:5],
            },
        }

    def _probe_base45_text(self, text: str) -> dict[str, Any]:
        normalized = re.sub(r"[\r\n\t]+", "", text).strip()
        if len(normalized) < 6 or any(char not in BASE45_ALPHABET for char in normalized):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 48
        reasons = ["字符集落在 Base45 的常见字母表范围内。"]
        if " " in normalized:
            score += 4
            reasons.append("包含 Base45 合法的空格字符。")
        if re.search(r"[$%*+\-./:]", normalized):
            score += 8
            reasons.append("包含 Base45 常见的符号字符。")
        if re.fullmatch(r"[A-Z ]+", normalized):
            score -= 18
            reasons.append("文本也可能只是普通大写字符串，因此需要依赖试解码进一步确认。")

        decoded_text = self._decode_base45_text(normalized)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=56, strict_decoded=True)

    def _probe_base58_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 8 or any(char not in BASE58_ALPHABET for char in compact):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 50
        reasons = ["字符集满足 Bitcoin 风格 Base58 的常见取值范围。"]
        if any(char.isdigit() for char in compact) and any(char.isalpha() for char in compact):
            score += 8
            reasons.append("同时包含数字和字母，接近常见 Base58 样本形态。")
        if any(char in compact for char in "0OIl"):
            return {"score": 0, "reason": "", "decoded_text": None}

        decoded_text = self._decode_base58_text(compact)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=58, strict_decoded=True)

    def _probe_base62_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 10 or not compact.isalnum():
            return {"score": 0, "reason": "", "decoded_text": None}
        if compact.isalpha() or compact.isdigit():
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 36
        reasons = ["输入是纯字母数字串，形式上可尝试 Base62。"]
        if any(char.islower() for char in compact) and any(char.isupper() for char in compact) and any(char.isdigit() for char in compact):
            score += 12
            reasons.append("同时包含大小写字母和数字，更接近 Base62 的常见样本。")
        else:
            score -= 8
            reasons.append("缺少大小写和数字的混合特征，因此 Base62 证据偏弱。")

        decoded_text = self._decode_base62_text(compact)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=62, strict_decoded=True)

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
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55)

    def _probe_base85_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 5:
            return {"score": 0, "reason": "", "decoded_text": None}
        if any(ord(char) < 33 or ord(char) > 117 for char in compact):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 44
        reasons = ["字符集落在 Ascii85/Base85 默认的可打印范围内。"]
        if re.search(r"[!\"#$%&'()*+,./:;<=>?@[\\\]^_`{|}~]", compact):
            score += 8
            reasons.append("包含较多符号字符，接近 Base85 样本形态。")

        decoded_text = self._decode_base85_text(text)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=58, strict_decoded=True)

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
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55)

    def _probe_hex_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 8 or len(compact) % 2 != 0 or not re.fullmatch(r"[A-Fa-f0-9]+", compact):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 78
        reasons = ["输入几乎完全由十六进制字符组成，适合优先尝试 From Hex。"]
        if any(char.isalpha() for char in compact) and any(char.isdigit() for char in compact):
            score += 6
            reasons.append("同时包含字母和数字，接近常见十六进制字节流。")

        decoded_text = self._decode_hex_text(compact)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=54, strict_decoded=True)

    def _probe_binary_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 24 or not re.fullmatch(r"[01]+", compact):
            if not re.fullmatch(r"(?:[01]{8}(?:[\s,;:/\\|]+|$)){3,}", text.strip()):
                return {"score": 0, "reason": "", "decoded_text": None}

        score = 84
        reasons = ["输入主要由 0 和 1 组成，且分组形态接近按字节表示的二进制文本。"]
        if re.search(r"[\s,;:/\\|]", text):
            score += 4
            reasons.append("存在分隔符，符合常见二进制字节串写法。")

        decoded_text = self._decode_binary_text(text)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55, strict_decoded=True)

    def _probe_octal_text(self, text: str) -> dict[str, Any]:
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 9 or not re.fullmatch(r"[0-7]+", compact):
            if not re.fullmatch(r"(?:[0-7]{3}(?:[\s,;:/\\|]+|$)){3,}", text.strip()):
                return {"score": 0, "reason": "", "decoded_text": None}

        score = 74
        reasons = ["输入由 0-7 数字组成，分组形态接近八进制字节表示。"]
        if re.search(r"[\s,;:/\\|]", text):
            score += 6
            reasons.append("存在分隔符，符合常见八进制字节串写法。")

        decoded_text = self._decode_octal_text(text)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55, strict_decoded=True)

    def _probe_quoted_printable_text(self, text: str) -> dict[str, Any]:
        if not (re.search(r"=[0-9A-Fa-f]{2}", text) or re.search(r"=\r?\n", text)):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 86
        reasons = ["输入包含 =XX 或软换行，符合 Quoted Printable 的典型特征。"]
        decoded_text = self._decode_quoted_printable_text(text)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55, strict_decoded=True)

    def _probe_morse_text(self, text: str) -> dict[str, Any]:
        normalized = text.strip()
        if len(normalized) < 5 or not re.fullmatch(r"[.\-\s/|\\]+", normalized):
            return {"score": 0, "reason": "", "decoded_text": None}
        if len(re.findall(r"[.-]+", normalized)) < 3:
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 78
        reasons = ["输入主要由点、横线和分隔符组成，接近 Morse Code / 摩斯电码。"]
        if any(token in normalized for token in ["/", "|", "\\", "\n"]):
            score += 6
            reasons.append("包含单词分隔符，符合常见摩斯编码写法。")

        decoded_text = self._decode_morse_text(normalized)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=58, strict_decoded=True)

    def _probe_rot13_text(self, text: str) -> dict[str, Any]:
        letters = re.findall(r"[A-Za-z]", text)
        if len(letters) < 6 or not re.fullmatch(r"[A-Za-z0-9\s.,:;!?_/\-+'\"()\[\]{}]+", text):
            return {"score": 0, "reason": "", "decoded_text": None}

        decoded_text = self._decode_rot13_text(text)
        if not decoded_text or decoded_text == text:
            return {"score": 0, "reason": "", "decoded_text": None}

        source_hits = self._common_text_token_hits(text)
        decoded_hits = self._common_text_token_hits(decoded_text)
        if decoded_hits <= source_hits:
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 54
        reasons = ["输入主要由英文字母和常见标点组成，可尝试 ROT13。"]
        score += 16
        reasons.append("ROT13 后出现更明显的常见英文或 CTF 关键词。")

        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=68, strict_decoded=True)

    def _probe_url_text(self, text: str) -> dict[str, Any]:
        percent_hits = re.findall(r"%[0-9A-Fa-f]{2}", text)
        if not percent_hits:
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 84 if len(percent_hits) < 2 else 90
        reasons = [f"输入中包含 {len(percent_hits)} 个 %xx 片段，典型于 URL 编码。"]
        decoded_text = unquote(text)
        if decoded_text == text:
            decoded_text = None
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55, strict_decoded=True)

    def _probe_unicode_escape_text(self, text: str) -> dict[str, Any]:
        if not re.search(r"(?:\\u|%u|U\+)[0-9A-Fa-f]{4,6}", text):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 88
        reasons = ["输入包含明显的 Unicode Escape / \\uXXXX / %uXXXX / U+XXXX 片段。"]
        decoded_text = self._decode_unicode_escape_text(text)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55, strict_decoded=True)

    def _probe_html_entity_text(self, text: str) -> dict[str, Any]:
        if not ("&#" in text or "&amp;" in text.lower() or re.search(r"&[A-Za-z]{2,10};", text)):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 82
        reasons = ["输入包含 HTML 实体编码特征。"]
        decoded_text = html.unescape(text)
        if decoded_text == text:
            decoded_text = None
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55, strict_decoded=True)

    def _probe_json_escape_text(self, text: str) -> dict[str, Any]:
        if not (re.search(r"\\[\"\\/bfnrt]", text) or re.search(r"\\u[0-9A-Fa-f]{4}", text)):
            return {"score": 0, "reason": "", "decoded_text": None}

        score = 76
        reasons = ["输入中包含 JSON 风格的反斜杠转义序列。"]
        decoded_text = self._decode_json_escape_text(text)
        return self._finalize_decoded_probe(score, reasons, decoded_text, min_reliability=55, strict_decoded=True)

    def _discover_encoding_recipe(self, text: str, max_depth: int = 3) -> tuple[list[str], list[dict[str, Any]]]:
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
        for name, probe_func, threshold in (
            ("Base45", self._probe_base45_text, 72),
            ("Base58", self._probe_base58_text, 72),
            ("Base62", self._probe_base62_text, 72),
            ("Base64", self._probe_base64_text, 76),
            ("Base85", self._probe_base85_text, 72),
            ("Base32", self._probe_base32_text, 76),
            ("Hex", self._probe_hex_text, 76),
            ("Binary", self._probe_binary_text, 76),
            ("Octal", self._probe_octal_text, 72),
            ("Quoted Printable", self._probe_quoted_printable_text, 76),
            ("Morse Code", self._probe_morse_text, 76),
            ("ROT13", self._probe_rot13_text, 70),
            ("URL", self._probe_url_text, 76),
            ("Unicode Escape", self._probe_unicode_escape_text, 76),
            ("HTML Entity", self._probe_html_entity_text, 72),
            ("JSON Escape", self._probe_json_escape_text, 72),
        ):
            probe = probe_func(text)
            if int(probe["score"]) >= threshold and probe.get("decoded_text"):
                candidates.append({"name": name, **probe})

        if not candidates:
            return None
        return max(candidates, key=lambda item: int(item["score"]))

    def _best_nested_encoding_hint(self, text: str) -> str | None:
        if getattr(self, "_disable_nested_probe_hints", False):
            return None

        previous_state = getattr(self, "_disable_nested_probe_hints", False)
        self._disable_nested_probe_hints = True
        try:
            probe = self._best_structured_encoding_probe(text)
        finally:
            self._disable_nested_probe_hints = previous_state
        if not probe:
            return None
        return str(probe["name"])

    def _encoding_step_name(self, encoding_name: str) -> str | None:
        normalized = encoding_name.strip().lower()
        mapping = {
            "base45": "From Base45",
            "base58": "From Base58",
            "base62": "From Base62",
            "base64": "From Base64",
            "base85": "From Base85",
            "base32": "From Base32",
            "hex": "From Hex",
            "binary": "From Binary",
            "octal": "From Octal",
            "quoted printable": "From Quoted Printable",
            "morse code": "From Morse Code",
            "rot13": "ROT13",
            "url": "URL Decode",
            "unicode escape": "Unescape Unicode Characters",
            "html entity": "From HTML Entity",
            "json escape": "Unescape Unicode Characters",
        }
        if normalized in {"utf-8", "utf8", "gbk", "gb18030", "utf-16", "utf-16le", "utf-16be"}:
            return "Decode text"
        return mapping.get(normalized)

    def _finalize_decoded_probe(
        self,
        score: int,
        reasons: list[str],
        decoded_text: str | None,
        *,
        min_reliability: int = 55,
        strict_decoded: bool = False,
    ) -> dict[str, Any]:
        if not decoded_text:
            if strict_decoded:
                return {"score": 0, "reason": "", "decoded_text": None}
            return {
                "score": max(0, min(100, score)),
                "reason": " ".join(reasons),
                "decoded_text": None,
                "preview": "",
            }

        reliability = self._decoded_text_reliability(decoded_text)
        nested_hint = None if getattr(self, "_disable_nested_probe_hints", False) else self._best_nested_encoding_hint(decoded_text)
        if strict_decoded and reliability < min_reliability and not nested_hint:
            return {"score": 0, "reason": "", "decoded_text": None}

        if reliability >= min_reliability:
            score += 18
            reasons.append(f"试解码后得到可读片段：{self._truncate_encoding_preview(decoded_text)}。")
        elif nested_hint:
            score += 12
            reasons.append(f"试解码后一层仍明显像 {nested_hint}。")
        else:
            score -= 12

        return {
            "score": max(0, min(100, score)),
            "reason": " ".join(reasons),
            "decoded_text": decoded_text,
            "preview": self._truncate_encoding_preview(decoded_text),
        }

    def _decoded_text_reliability(self, value: str | None) -> int:
        text = self._optional_text(value) or ""
        if not text:
            return 0

        printable_ratio = self._text_printable_ratio(text)
        if printable_ratio < 0.6:
            return 0

        ascii_ratio = sum(1 for char in text if char in "\n\r\t" or 32 <= ord(char) <= 126) / len(text)
        score = int(printable_ratio * 45)
        if ascii_ratio >= 0.85:
            score += 10
        if re.search(r"[\u4e00-\u9fff]", text):
            score += 16
        elif re.search(r"[A-Za-z]", text):
            score += 12
        if re.search(r"\s", text):
            score += 8

        token_hits = self._common_text_token_hits(text)
        if token_hits >= 1:
            score += 10
        if token_hits >= 2:
            score += 8

        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
            score -= 18
        if "�" in text:
            score -= 18
        if len(text) >= 8 and not re.search(r"\s", text) and token_hits == 0 and ascii_ratio < 0.75:
            score -= 8

        return max(0, min(100, score))

    def _common_text_token_hits(self, value: str) -> int:
        lowered = value.lower()
        tokens = (
            "flag{",
            "ctf{",
            "hello",
            "world",
            "http",
            "https",
            "json",
            "xml",
            "html",
            "select ",
            "from ",
            "where ",
            "user",
            "admin",
            "login",
            "cookie",
            "token",
            "password",
            "hash",
            "base64",
            "md5",
            "sha1",
            "sha256",
        )
        return sum(1 for token in tokens if token in lowered)

    def _decode_base_n_bytes(self, value: str, alphabet: str) -> bytes | None:
        if not value:
            return None

        lookup = {char: index for index, char in enumerate(alphabet)}
        number = 0
        for char in value:
            digit = lookup.get(char)
            if digit is None:
                return None
            number = (number * len(alphabet)) + digit

        if number == 0:
            decoded = b""
        else:
            decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")

        leading_zero_char = alphabet[0]
        leading_zero_count = len(value) - len(value.lstrip(leading_zero_char))
        return (b"\x00" * leading_zero_count) + decoded

    def _decode_base45_text(self, value: str) -> str | None:
        normalized = re.sub(r"[\r\n\t]+", "", value).strip()
        if not normalized or len(normalized) % 3 == 1:
            return None

        lookup = {char: index for index, char in enumerate(BASE45_ALPHABET)}
        decoded = bytearray()
        index = 0
        try:
            while index < len(normalized):
                if index + 2 < len(normalized):
                    number = (
                        lookup[normalized[index]]
                        + (lookup[normalized[index + 1]] * 45)
                        + (lookup[normalized[index + 2]] * 45 * 45)
                    )
                    if number > 0xFFFF:
                        return None
                    decoded.extend(divmod(number, 256))
                    index += 3
                else:
                    number = lookup[normalized[index]] + (lookup[normalized[index + 1]] * 45)
                    if number > 0xFF:
                        return None
                    decoded.append(number)
                    index += 2
        except KeyError:
            return None

        return self._decode_bytes_to_text(bytes(decoded))

    def _decode_base58_text(self, value: str) -> str | None:
        decoded = self._decode_base_n_bytes(value, BASE58_ALPHABET)
        if decoded is None:
            return None
        return self._decode_bytes_to_text(decoded)

    def _decode_base62_text(self, value: str) -> str | None:
        decoded = self._decode_base_n_bytes(value, BASE62_ALPHABET)
        if decoded is None:
            return None
        return self._decode_bytes_to_text(decoded)

    def _decode_base64_text(self, value: str) -> str | None:
        normalized = value.replace("-", "+").replace("_", "/")
        padded = normalized + ("=" * (-len(normalized) % 4))
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return None
        return self._decode_bytes_to_text(decoded)

    def _decode_base85_text(self, value: str) -> str | None:
        try:
            decoded = base64.a85decode(value.encode("ascii"), adobe=False, ignorechars=b" \t\n\r\x0b")
        except (UnicodeEncodeError, ValueError, binascii.Error):
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

    def _decode_binary_text(self, value: str) -> str | None:
        compact = re.sub(r"\s+", "", value)
        groups: list[str]
        if compact and re.fullmatch(r"[01]+", compact) and len(compact) % 8 == 0:
            groups = [compact[index : index + 8] for index in range(0, len(compact), 8)]
        else:
            groups = re.findall(r"[01]{8}", value)
            if not groups:
                return None
            cleaned = re.sub(r"[01]{8}", "", value)
            if cleaned.strip().strip(",;:/\\|"):
                return None

        decoded = bytes(int(group, 2) for group in groups)
        return self._decode_bytes_to_text(decoded)

    def _decode_octal_text(self, value: str) -> str | None:
        compact = re.sub(r"\s+", "", value)
        groups: list[str]
        if compact and re.fullmatch(r"[0-7]+", compact) and len(compact) % 3 == 0:
            groups = [compact[index : index + 3] for index in range(0, len(compact), 3)]
        else:
            groups = re.findall(r"[0-7]{3}", value)
            if not groups:
                return None
            cleaned = re.sub(r"[0-7]{3}", "", value)
            if cleaned.strip().strip(",;:/\\|"):
                return None

        try:
            decoded = bytes(int(group, 8) for group in groups)
        except ValueError:
            return None
        return self._decode_bytes_to_text(decoded)

    def _decode_quoted_printable_text(self, value: str) -> str | None:
        try:
            decoded = quopri.decodestring(value)
        except ValueError:
            return None
        text = self._decode_bytes_to_text(decoded)
        return text if text and text != value else None

    def _decode_morse_text(self, value: str) -> str | None:
        normalized = value.strip()
        if not normalized:
            return None

        normalized = normalized.replace("\r\n", "\n")
        normalized = normalized.replace("|", " / ")
        normalized = normalized.replace("\\", " / ")
        normalized = re.sub(r"\s*/\s*", " / ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()

        words = [chunk.strip() for chunk in normalized.split(" / ") if chunk.strip()]
        if not words:
            return None

        decoded_words: list[str] = []
        for word in words:
            letters: list[str] = []
            for token in word.split(" "):
                char = MORSE_CODE_TABLE.get(token)
                if char is None:
                    return None
                letters.append(char)
            decoded_words.append("".join(letters))

        decoded_text = " ".join(decoded_words)
        return decoded_text if decoded_text else None

    def _decode_rot13_text(self, value: str) -> str | None:
        source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        target = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        translated = value.translate(str.maketrans(source, target))
        return translated if translated and translated != value else None

    def _decode_unicode_escape_text(self, value: str) -> str | None:
        normalized = re.sub(r"%u([0-9A-Fa-f]{4})", r"\\u\1", value)
        normalized = re.sub(r"U\+([0-9A-Fa-f]{4,6})", lambda match: f"\\u{match.group(1)[-4:]}", normalized)
        try:
            decoded = normalized.encode("utf-8").decode("unicode_escape")
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

    def _normalize_hash_result_assist_payload(self, payload: dict[str, Any], raw_input: str | None = None) -> dict[str, Any]:
        detected_primary = self._detect_hash_topic(raw_input or "")
        default_primary = detected_primary if detected_primary != "HASH" else "SHA256"
        primary_hash = str(payload.get("primary_hash") or payload.get("preferred_hash") or default_primary).strip() or default_primary
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

    def _build_timestamp_knowledge_fallback(self, raw_input: str) -> dict[str, Any]:
        timestamp_type = self._detect_timestamp_topic(raw_input)
        topic_map = {
            "unix": "Unix 时间戳通常表示自 1970-01-01 00:00:00 UTC 起经过的秒数或其放大单位，常用于跨系统统一记录时间。",
            "windows_filetime": "Windows FileTime 通常表示自 1601-01-01 00:00:00 UTC 起经过的 100 纳秒间隔，常见于 Windows 文件元数据和注册表时间字段。",
            "chrome_webkit": "Chrome/WebKit 时间戳通常表示自 1601-01-01 00:00:00 UTC 起经过的微秒数，常见于浏览器历史、Cookie 等 SQLite 数据。",
            "apple_absolute_time": "Apple Absolute Time 通常表示自 2001-01-01 00:00:00 UTC 起经过的秒数，常见于 Apple 生态的部分时间字段。",
            "ios": "iOS 时间字段常见来源较杂，既可能是 Unix 秒/毫秒，也可能是 Cocoa/Apple Absolute Time，需要结合字段语义一起判断。",
            "dotnet_ticks": ".NET Ticks 通常表示自公元 0001-01-01 00:00:00 起经过的 100 纳秒间隔，常见于 .NET 程序序列化或日志字段。",
            "auto": "时间戳识别通常先看数值长度、时间起点、单位粒度和字段上下文，再判断属于 Unix、FileTime、WebKit 还是其他格式。",
        }
        return {
            "timestamp": "",
            "timestamp_type": timestamp_type,
            "origin_timezone": "UTC",
            "target_timezone": "Asia/Shanghai",
            "explanation": topic_map.get(timestamp_type, topic_map["auto"]),
            "confidence": "medium",
            "warnings": ["当前回答基于通用知识，未结合具体时间戳原值做识别。"],
        }

    def _build_hashcat_knowledge_fallback(self, raw_input: str, current_form: dict[str, Any], default_wordlist_name: str | None) -> dict[str, Any]:
        lowered = raw_input.lower()
        hash_mode_map = {
            "ntlm": 1000,
            "sha512": 1700,
            "sha-512": 1700,
            "sha256": 1400,
            "sha-256": 1400,
            "sha1": 100,
            "sha-1": 100,
            "md5": 0,
        }
        hash_mode = next((mode for keyword, mode in hash_mode_map.items() if keyword in lowered), 0)

        attack_mode = 0
        explanation = "Hashcat 主要用于离线口令恢复，常见思路是先确认 hash 类型，再按字典、掩码或组合模式选择攻击方式。"
        if any(keyword in lowered for keyword in ("combinator", "组合模式", "组合字典", "双字典", "两个字典")):
            attack_mode = 1
            explanation = "组合模式对应 attack_mode=1，适合把两个字典按前后顺序组合生成候选口令。"
        elif ("前缀" in raw_input or "prefix" in lowered) and ("mask" in lowered or "掩码" in raw_input):
            attack_mode = 7
            explanation = "混合模式 7 表示“掩码前缀 + 字典”，适合前面补固定规则字符、后面接词典词。"
        elif any(keyword in lowered for keyword in ("后缀", "suffix", "末尾", "尾部")) and ("mask" in lowered or "掩码" in raw_input):
            attack_mode = 6
            explanation = "混合模式 6 表示“字典 + 掩码后缀”，适合词典词后面再补几位数字或固定字符。"
        elif "mask" in lowered or "掩码" in raw_input:
            attack_mode = 3
            explanation = "掩码模式对应 attack_mode=3，适合已知口令结构、长度和字符集的大致范围时做定向爆破。"

        current_wordlist = self._optional_text(current_form.get("wordlist_path"))
        return {
            "hash_mode": hash_mode,
            "attack_mode": attack_mode,
            "wordlist_path": current_wordlist or default_wordlist_name,
            "secondary_wordlist_path": None,
            "mask": None,
            "session_name": None,
            "extra_args": [],
            "explanation": explanation,
            "confidence": "medium",
            "warnings": ["当前回答基于通用 Hashcat 知识，未结合具体 hash 样本验证 hash_mode。"],
        }

    def _build_encoding_knowledge_fallback(self, raw_input: str) -> dict[str, Any]:
        lowered = raw_input.lower()
        if "base64" in lowered and "base32" in lowered and ("区别" in raw_input or "差异" in raw_input or "difference" in lowered):
            return {
                "recommended_encoding": "Base64",
                "candidates": [
                    {"name": "Base64", "score": 90, "confidence": "high", "reason": "问题明确在比较 Base64 与 Base32 的差异。"},
                    {"name": "Base32", "score": 90, "confidence": "high", "reason": "问题明确在比较 Base64 与 Base32 的差异。"},
                ],
                "suggested_recipe": ["From Base64"],
                "cyberchef_recipe": "From_Base64('A-Za-z0-9+/=',true,false)",
                "cyberchef_input": raw_input.strip(),
                "explanation": "Base64 与 Base32 都是编码表示而不是加密。Base64 字符集更宽，体积膨胀更小；Base32 字符集更受限，更适合对大小写或特殊字符敏感的场景。",
                "warnings": ["当前回答基于通用知识，未结合具体编码样本做识别。"],
            }

        topic = self._detect_encoding_topic(raw_input)
        explanation_map = {
            "Base45": "Base45 使用 45 个可打印字符表示二进制数据，常见于二维码和受限字符集场景，效率通常介于 Base32 与 Base64 之间。",
            "Base58": "Base58 会排除 0、O、I、l 这类易混淆字符，常见于加密货币地址、短链接或需要人工抄录的标识串。",
            "Base62": "Base62 通常使用 0-9、A-Z、a-z 表示数据，常见于短链、邀请码和 CTF 题目，但不同实现对字母表和前导零处理可能不完全一致。",
            "Base64": "Base64 是一种把二进制数据映射为可打印字符的表示方式，常用于传输和封装，不属于加密。",
            "Base85": "Base85/Ascii85 用更大的字符表来表示二进制，体积通常比 Base64 更紧凑，但可读性和兼容性相对更差。",
            "Base32": "Base32 同样是二进制到文本的表示方式，字符集更受限，常见为 A-Z、2-7 和 =，更适合对大小写或字符集敏感的场景。",
            "Hex": "Hex 是把每个字节表示为两个十六进制字符的方式，可读性强，但体积通常比原始数据更大。",
            "Binary": "Binary 通常把每个字节写成 8 位 0/1 串，教学和竞赛场景常见，但体积大、人工阅读成本高。",
            "Octal": "Octal 会把字节表示成八进制数字，常见于旧式转义、脚本片段和部分 CTF 题目。",
            "Quoted Printable": "Quoted Printable 常用于电子邮件正文传输，把不可打印字符写成 =XX 形式，同时尽量保留原有可读文本。",
            "Morse Code": "Morse Code 通过点和横线表示字母数字，竞赛里常用于基础编码题或多层包装链路。",
            "ROT13": "ROT13 是把英文字母循环平移 13 位的替换方式，本质上属于非常弱的字母轮换，不适合作为安全加密，只适合简单混淆或谜题。",
            "URL": "URL 编码会把特殊字符转为 %xx 形式，常见于查询参数、表单和 Web 请求链路。",
            "Unicode Escape": "Unicode Escape 常用 \\uXXXX 形式表示字符编码点，常见于脚本、JSON 片段和转义字符串。",
            "HTML Entity": "HTML Entity 用于在 HTML 中安全表示特殊字符，例如 &amp;、&#x41; 等。",
            "JSON Escape": "JSON Escape 使用反斜杠对引号、换行、Unicode 等字符做转义，常见于接口返回和日志字段。",
            "Unknown": "当前问题像是在询问编码或表示形式的概念，但没有明确命中特定的 CTF/取证常见编码主题。",
            "GBK": "GBK 是中文场景常见字符集，常见问题是与 UTF-8 相互误解码后出现乱码。",
            "GB18030": "GB18030 是对中文字符覆盖更完整的多字节字符集，在本地取证和旧系统中比较常见。",
            "UTF-16LE": "UTF-16LE 常以双字节形式存储文本，Windows 场景较常见，处理时要注意字节序和 BOM。",
            "UTF-16BE": "UTF-16BE 与 UTF-16LE 的区别主要在字节序，误判字节序会导致明显乱码。",
            "UTF-8": "UTF-8 是当前最常见的通用文本编码，兼容 ASCII，跨平台交换文本时通常优先考虑它。",
        }
        recipe_steps = []
        step_name = self._encoding_step_name(topic)
        if step_name:
            recipe_steps = [step_name]
        candidates: list[dict[str, Any]] = [
            {
                "name": topic,
                "score": 92,
                "confidence": "high",
                "reason": "问题本身在询问该编码或表示形式的概念，用通用知识先回答更合适。",
            }
        ]
        if topic == "Base64":
            candidates.append({"name": "Base32", "score": 62, "confidence": "medium", "reason": "Base32 与 Base64 常被一起比较，主要差异在字符集和体积开销。"})
        elif topic == "Base32":
            candidates.append({"name": "Base64", "score": 62, "confidence": "medium", "reason": "Base64 与 Base32 常被一起比较，主要差异在字符集和体积开销。"})
        elif topic == "Base58":
            candidates.append({"name": "Base62", "score": 60, "confidence": "medium", "reason": "Base58 与 Base62 都是字母数字族编码，常见差异在字符表是否排除易混淆字符。"})
        elif topic == "Base62":
            candidates.append({"name": "Base58", "score": 60, "confidence": "medium", "reason": "Base62 与 Base58 都常见于短串表示，主要差异在字母表和实现约定。"})
        elif topic == "Quoted Printable":
            candidates.append({"name": "Base64", "score": 54, "confidence": "medium", "reason": "Quoted Printable 与 Base64 都常见于邮件场景，但侧重点分别是可读性和压缩效率。"})
        elif topic == "Morse Code":
            candidates.append({"name": "ROT13", "score": 40, "confidence": "low", "reason": "两者都常出现在基础编码题中，但原理完全不同。"})

        return {
            "recommended_encoding": topic,
            "candidates": candidates,
            "suggested_recipe": recipe_steps,
            "cyberchef_recipe": self._build_cyberchef_recipe_from_suggestions(recipe_steps, topic),
            "cyberchef_input": raw_input.strip(),
            "explanation": explanation_map.get(topic, explanation_map["Unknown"]),
            "warnings": ["当前回答基于通用知识，未结合具体编码样本做识别。"],
        }

    def _build_hash_knowledge_fallback(self, raw_input: str) -> dict[str, Any]:
        lowered = raw_input.lower()
        if "md5" in lowered and "sha256" in lowered and ("区别" in raw_input or "差异" in raw_input or "difference" in lowered):
            return {
                "summary": "MD5 和 SHA256 都是消息摘要算法，但 SHA256 在抗碰撞和完整性校验稳健性方面明显更强。",
                "primary_hash": "SHA256",
                "findings": [
                    "MD5 长度更短、计算更快，但已存在成熟碰撞风险，更适合作为兼容性补充而不是唯一强校验值。",
                    "SHA256 兼顾强度与通用性，在取证完整性校验、样本比对和交接留痕里通常更适合作为主哈希。",
                ],
                "recommendations": [
                    "如果流程允许，优先记录 SHA256，并把 MD5 作为兼容旧平台或旧情报库的补充摘要。",
                    "在报告和证据交接中，不要只保留 MD5，最好至少保留一个强哈希值。",
                    "若后续要落到具体案件，再结合文件来源、大小和获取时间一起分析会更准确。",
                ],
                "warnings": ["当前回答基于通用知识，未结合具体文件哈希结果。"],
                "confidence": "medium",
            }

        topic = self._detect_hash_topic(raw_input)
        summary_map = {
            "MD5": "MD5 是 128 位消息摘要算法，计算速度快，但已存在成熟碰撞风险，不适合作为安全强度依赖的唯一依据。",
            "SHA1": "SHA1 曾广泛用于完整性校验，但也已存在实际碰撞风险，更适合作为兼容性补充而不是唯一强校验值。",
            "SHA256": "SHA256 属于 SHA-2 系列，当前仍是取证完整性校验和跨平台样本比对中更稳妥的主摘要选择之一。",
            "SHA512": "SHA512 输出更长，抗碰撞能力更强，但在部分平台或流程里通用性不如 SHA256。",
            "SM3": "SM3 是国产密码摘要算法，适合需要满足特定合规要求或国密体系兼容的场景。",
            "HASH": "哈希值本质上是把任意长度输入映射成固定长度摘要，常用于完整性校验、样本索引和证据留存。",
        }
        findings_map = {
            "MD5": [
                "MD5 仍可用于快速去重、旧系统兼容和历史情报索引，但不建议单独承担高强度完整性证明。",
                "在取证报告中，MD5 更适合作为兼容性补充，通常应同时记录 SHA256 一类更强摘要。",
            ],
            "SHA1": [
                "SHA1 在旧生态里兼容性较好，但由于碰撞风险，通常不应作为唯一可信校验值。",
                "如果历史平台只支持 SHA1，建议同时补充 SHA256 或 SHA512 提高证据稳健性。",
            ],
            "SHA256": [
                "SHA256 兼顾强度与通用性，适合在报告、交接和复算核验中作为主哈希记录。",
                "同一文件在不同环节重复计算 SHA256 并比对，可有效验证传输和导出过程是否被篡改。",
            ],
            "SHA512": [
                "SHA512 输出更长，适合对碰撞安全边界要求更高的校验场景。",
                "若对接平台默认只接受 SHA256，可保留 SHA512 作为补充而不是替代。",
            ],
            "SM3": [
                "SM3 在部分合规或国产化环境中更有现实价值，适合与现有国密体系联动使用。",
                "若案件流程同时涉及国际平台和国密平台，可并行保留 SM3 与 SHA256 提高兼容性。",
            ],
            "HASH": [
                "哈希常见用途包括完整性校验、样本去重、情报检索和证据链固定。",
                "哈希不是加密，不能从摘要直接还原原文，但也不能把它当成对文件内容真实性的唯一背景解释。",
            ],
        }
        return {
            "summary": summary_map.get(topic, summary_map["HASH"]),
            "primary_hash": topic if topic != "HASH" else "SHA256",
            "findings": findings_map.get(topic, findings_map["HASH"]),
            "recommendations": [
                "如果后续要落到具体案件，请同时记录文件名、大小、获取时间和至少一个强哈希值。",
                "若涉及跨平台比对或外部情报检索，优先准备 SHA256，再按目标平台需要补充其他摘要。",
                "一旦有具体哈希结果，再结合案件背景、样本库和交接链路做针对性分析会更准确。",
            ],
            "warnings": ["当前回答基于通用知识，未结合具体文件哈希结果。"],
            "confidence": "medium",
        }

    def _build_sqlite_knowledge_fallback(self, raw_input: str) -> dict[str, Any]:
        lowered = raw_input.lower()
        summary = "SQLite 是轻量级嵌入式数据库，常见于浏览器、聊天软件、移动应用和本地客户端取证场景。"
        schema_notes = [
            "取证时通常先看表名、字段名、主键、时间字段和是否存在 BLOB/JSON 等复合内容。",
            "高价值表名常见关键词包括 user、account、message、history、event、login、session、file、attach。",
        ]
        if "wal" in lowered:
            summary = "SQLite 的 WAL 文件记录了未合并回主库的写前日志，取证时常能补到主库里暂未体现的近期变更。"
            schema_notes.insert(0, "如果同时拿到 .db、-wal、-shm，分析时要把三者一起考虑，避免遗漏近期写入。")
        elif "索引" in raw_input or "index" in lowered:
            summary = "SQLite 索引主要用于加速查询，本身未必直接存新数据，但能帮助判断字段关联和检索路径。"
        elif "主键" in raw_input or "primary key" in lowered:
            summary = "SQLite 主键通常用于唯一标识记录，取证时可借此做去重、关联和增量比对。"

        return {
            "summary": summary,
            "highlighted_tables": [],
            "current_table_name": None,
            "focus_fields": [],
            "schema_notes": schema_notes,
            "recommendations": [
                "拿到具体数据库后，先浏览表结构，再按时间字段、账号字段、消息字段和路径字段做优先级排序。",
                "如果同时存在主库、WAL 和缓存文件，建议一并保留并交叉验证时间线。",
                "有了具体表和字段后，我可以继续帮你判断优先导出哪些表、哪些字段最有价值。",
            ],
            "warnings": ["当前回答基于通用 SQLite 取证经验，未结合具体数据库结构。"],
        }

    def _assist_timestamp_fallback(self, raw_input: str) -> dict[str, Any]:
        text = raw_input.strip()
        if self._is_knowledge_question(text) and not re.search(r"[-+]?\d+(?:\.\d+)?", text):
            return self._build_timestamp_knowledge_fallback(text)

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

        if self._is_knowledge_question(text):
            result = self._build_hashcat_knowledge_fallback(text, current_form, default_wordlist_name)
            if sample_lines or sample_hashes:
                result["warnings"] = self._merge_text_lists(
                    list(result.get("warnings") or []),
                    ["当前存在样本或表单上下文，但本次问题属于知识问答，返回的是通用说明而不是针对样本的最终配置。"],
                )
            return result

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
        if self._is_knowledge_question(raw_input):
            return self._build_encoding_knowledge_fallback(raw_input)
        return self._analyze_encoding_input(raw_input)

    def _assist_hash_result_fallback(self, raw_input: str, context: dict[str, Any]) -> dict[str, Any]:
        hash_result = context.get("hash_result")
        warnings: list[str] = []
        findings: list[str] = []
        recommendations: list[str] = []
        confidence = "medium"

        if self._is_knowledge_question(raw_input):
            result = self._build_hash_knowledge_fallback(raw_input)
            extra_findings: list[str] = []
            extra_warnings: list[str] = []
            if isinstance(hash_result, dict):
                file_name = str(hash_result.get("file_name") or "当前文件")
                algorithms = hash_result.get("algorithms") or []
                algorithms_upper = [str(item).upper() for item in algorithms if str(item).strip()]
                if algorithms_upper:
                    extra_findings.append(f"当前文件“{file_name}”已经生成这些摘要：{'、'.join(algorithms_upper)}，后续可继续结合实际结果落地分析。")
                extra_warnings.append("本次先回答通用知识；如果你想落到当前文件，我可以继续结合现有摘要结果细化用途建议。")
            else:
                extra_warnings.append("未检测到 hash_result 上下文，因此本次先回答通用知识与通用做法。")
            result["findings"] = self._merge_text_lists(list(result.get("findings") or []), extra_findings)
            result["warnings"] = self._merge_text_lists(list(result.get("warnings") or []), extra_warnings)
            return result

        if not isinstance(hash_result, dict):
            result = self._build_hash_knowledge_fallback(raw_input)
            result["warnings"] = self._merge_text_lists(
                list(result.get("warnings") or []),
                ["未检测到 hash_result 上下文，因此本次先回答通用知识与通用做法。"],
            )
            return result

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

        if self._is_knowledge_question(raw_input):
            result = self._build_sqlite_knowledge_fallback(raw_input)
            extra_notes: list[str] = []
            extra_warnings: list[str] = []
            if isinstance(browser, dict):
                database_name = str(browser.get("database_name") or "当前数据库")
                tables = browser.get("tables") or []
                table_count = len(tables) if isinstance(tables, list) else 0
                extra_notes.append(f"当前数据库“{database_name}”已加载，表数量约 {table_count} 张，后续可继续结合具体表结构做落地分析。")
                extra_warnings.append("本次先回答通用 SQLite 知识；如果你继续问具体表或字段，我会结合当前数据库上下文继续分析。")
            else:
                extra_warnings.append("未检测到 sqlite browser 上下文，因此本次先回答通用 SQLite 分析思路。")
            result["schema_notes"] = self._merge_text_lists(list(result.get("schema_notes") or []), extra_notes)
            result["warnings"] = self._merge_text_lists(list(result.get("warnings") or []), extra_warnings)
            return result

        if not isinstance(browser, dict):
            result = self._build_sqlite_knowledge_fallback(raw_input)
            result["warnings"] = self._merge_text_lists(
                list(result.get("warnings") or []),
                ["未检测到 sqlite browser 上下文，因此本次先回答通用 SQLite 分析思路。"],
            )
            return result

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

    def _is_knowledge_question(self, text: str) -> bool:
        normalized = text.strip().lower()
        if not normalized:
            return False
        patterns = (
            r"什么是",
            r"是什么",
            r"啥是",
            r"是啥",
            r"是什么意思",
            r"含义",
            r"原理",
            r"作用",
            r"用途",
            r"区别",
            r"差异",
            r"怎么理解",
            r"解释一下",
            r"介绍一下",
            r"科普",
            r"为什么",
            r"为何",
            r"优缺点",
            r"如何选择",
            r"怎么用",
            r"如何使用",
            r"what is",
            r"what's",
            r"difference",
            r"meaning",
            r"usage",
            r"use case",
        )
        return any(re.search(pattern, normalized) for pattern in patterns)

    def _detect_hash_topic(self, text: str) -> str:
        lowered = text.lower()
        if "sha512" in lowered or "sha-512" in lowered:
            return "SHA512"
        if "sha256" in lowered or "sha-256" in lowered:
            return "SHA256"
        if "sha1" in lowered or "sha-1" in lowered:
            return "SHA1"
        if "sm3" in lowered:
            return "SM3"
        if "md5" in lowered:
            return "MD5"
        return "HASH"

    def _detect_timestamp_topic(self, text: str) -> str:
        lowered = text.lower()
        if "filetime" in lowered or "windows" in lowered:
            return "windows_filetime"
        if "webkit" in lowered or "chrome" in lowered:
            return "chrome_webkit"
        if "apple absolute" in lowered or "cocoa" in lowered:
            return "apple_absolute_time"
        if "ios" in lowered:
            return "ios"
        if "tick" in lowered or ".net" in lowered:
            return "dotnet_ticks"
        if "unix" in lowered or "epoch" in lowered:
            return "unix"
        return "auto"

    def _detect_encoding_topic(self, text: str) -> str:
        lowered = text.lower()
        if "base45" in lowered:
            return "Base45"
        if "base58" in lowered:
            return "Base58"
        if "base62" in lowered:
            return "Base62"
        if "base85" in lowered or "ascii85" in lowered:
            return "Base85"
        if "base32" in lowered:
            return "Base32"
        if "base64" in lowered:
            return "Base64"
        if "hex" in lowered or "十六进制" in text:
            return "Hex"
        if "binary" in lowered or "二进制" in text:
            return "Binary"
        if "octal" in lowered or "八进制" in text:
            return "Octal"
        if "quoted printable" in lowered or "quoted-printable" in lowered or re.search(r"\bqp\b", lowered):
            return "Quoted Printable"
        if "morse" in lowered or "moss" in lowered or "摩斯" in text:
            return "Morse Code"
        if "rot13" in lowered or "凯撒" in text:
            return "ROT13"
        if "url" in lowered and ("编码" in text or "decode" in lowered or "转义" in text):
            return "URL"
        if "unicode" in lowered or "\\u" in text or "%u" in lowered or "u+" in lowered:
            return "Unicode Escape"
        if "html entity" in lowered or "html 实体" in text or "实体编码" in text:
            return "HTML Entity"
        if "json" in lowered and ("escape" in lowered or "转义" in text):
            return "JSON Escape"
        if "gb18030" in lowered:
            return "GB18030"
        if "gbk" in lowered:
            return "GBK"
        if "utf-16be" in lowered:
            return "UTF-16BE"
        if "utf-16le" in lowered or "utf16" in lowered:
            return "UTF-16LE"
        if "utf-8" in lowered or "utf8" in lowered:
            return "UTF-8"
        return "Unknown"

    def _extract_encoding_topics(self, text: str) -> list[str]:
        lowered = text.lower()
        topics: list[str] = []
        topic_rules = [
            ("Base45", ("base45",)),
            ("Base58", ("base58",)),
            ("Base62", ("base62",)),
            ("Base64", ("base64",)),
            ("Base85", ("base85", "ascii85")),
            ("Base32", ("base32",)),
            ("Hex", ("hex", "十六进制")),
            ("Binary", ("binary", "二进制")),
            ("Octal", ("octal", "八进制")),
            ("Quoted Printable", ("quoted printable", "quoted-printable")),
            ("Morse Code", ("morse", "moss", "摩斯")),
            ("ROT13", ("rot13", "凯撒")),
            ("URL", ("url", "url 编码", "url编码")),
            ("Unicode Escape", ("unicode escape", "unicode", "\\u", "%u", "u+")),
            ("HTML Entity", ("html entity", "html 实体", "实体编码")),
            ("JSON Escape", ("json escape", "json 转义")),
            ("GBK", ("gbk",)),
            ("GB18030", ("gb18030",)),
            ("UTF-16LE", ("utf-16le", "utf16le")),
            ("UTF-16BE", ("utf-16be", "utf16be")),
            ("UTF-8", ("utf-8", "utf8")),
        ]
        for topic, patterns in topic_rules:
            if topic == "Quoted Printable" and re.search(r"\bqp\b", lowered):
                topics.append(topic)
                continue
            if any(pattern in lowered or pattern in text for pattern in patterns):
                topics.append(topic)
        return topics

    def _detect_hashcat_topic(self, text: str) -> str:
        lowered = text.lower()
        if any(keyword in lowered for keyword in ("combinator", "组合模式", "双字典", "两个字典", "组合字典")):
            return "attack_mode_1"
        if "mask" in lowered or "掩码" in text:
            return "mask_mode"
        if "rule" in lowered or "规则" in text:
            return "rules"
        if "wordlist" in lowered or "字典" in text:
            return "wordlist"
        if "hash mode" in lowered or "hash_mode" in lowered or "hash类型" in text or "hash 类型" in text:
            return "hash_mode"
        return "hashcat"

    def _detect_sqlite_topic(self, text: str) -> str:
        lowered = text.lower()
        if "wal" in lowered:
            return "wal"
        if "主键" in text or "primary key" in lowered:
            return "primary_key"
        if "索引" in text or "index" in lowered:
            return "index"
        if "schema" in lowered or "结构" in text:
            return "schema"
        if "表" in text or "table" in lowered:
            return "table"
        return "sqlite"

    def _detect_log_topic(self, text: str) -> str:
        lowered = text.lower()
        if "error" in lowered and "warning" in lowered:
            return "error_warning_difference"
        if "error" in lowered:
            return "error"
        if "warning" in lowered or "warn" in lowered:
            return "warning"
        if "时间戳" in text or "timestamp" in lowered:
            return "timestamp"
        if "ip" in lowered or "网络" in text:
            return "ip"
        return "log_analysis"

    def _analyze_with_local_fallback(self, parsed_result: ParsedLogResponse, question: str) -> AIAnalysisResult:
        findings: list[FindingItem] = []
        timeline_summary: list[str] = []
        recommendations: list[str] = []

        if self._is_knowledge_question(question):
            lowered_question = question.lower()
            concept_title = "日志分析相关概念说明"
            concept_explanation = "日志分析的核心是把事件级原始记录还原为可验证的时间线，再判断哪些异常只是运行噪声，哪些异常足以支持取证结论。"
            if "error" in lowered_question and "warning" in lowered_question:
                concept_title = "Error 与 Warning 的区别"
                concept_explanation = "Error 通常表示已经发生失败、异常或功能受阻；Warning 更常表示风险提示、配置偏差或潜在问题，未必已经造成实际失败。"
            elif "error" in lowered_question:
                concept_title = "Error 日志的含义"
                concept_explanation = "Error 通常表示执行过程已经出现失败或异常，需要结合前后文确认失败点、影响范围和是否可复现。"
            elif "warning" in lowered_question or "warn" in lowered_question:
                concept_title = "Warning 日志的含义"
                concept_explanation = "Warning 更多是风险信号而不是直接定性结论，常用于提示配置异常、资源紧张、重试或潜在前置故障。"
            elif "时间戳" in question or "timestamp" in lowered_question:
                concept_title = "日志时间戳的作用"
                concept_explanation = "时间戳用于把分散事件串成可验证时间线，是日志取证里判断因果顺序、横向关联和复现轨迹的关键锚点。"
            elif "ip" in lowered_question or "网络" in question:
                concept_title = "日志中的网络线索"
                concept_explanation = "日志里的 IP、端口和主机名更适合与时间、账号、动作类型交叉验证，单独出现时通常只代表线索，不直接等于恶意结论。"

            findings.append(
                FindingItem(
                    title=concept_title,
                    evidence=[
                        f"当前日志共 {parsed_result.total_lines} 行。",
                        f"error 相关 {parsed_result.level_counts.error} 行，warning 相关 {parsed_result.level_counts.warning} 行。",
                    ],
                    explanation=concept_explanation,
                )
            )
            recommendations.extend(
                [
                    "先把通用概念和当前日志统计分开理解，避免把概念性判断直接当成案件结论。",
                    "如果你想继续落到当前日志，可再追问具体片段、时间线、IP 或某条异常的证据意义。",
                ]
            )

        if parsed_result.has_timestamp:
            timeline_summary.append("日志中检测到时间戳，可结合时间维度进一步复原事件顺序。")
        else:
            timeline_summary.append("日志中未明显检测到标准时间戳，时间线复原能力受限。")

        timeline_summary.append(f"本次共解析 {parsed_result.total_lines} 行日志。")
        timeline_summary.append(f"基础解析策略来源：{parsed_result.parse_strategy.source}。")

        if parsed_result.level_counts.error > 0 and not findings:
            findings.append(
                FindingItem(
                    title="检测到错误级别日志",
                    evidence=[f"error 相关行数：{parsed_result.level_counts.error}", *self._pick_evidence(parsed_result)],
                    explanation="日志中存在错误或异常关键字，说明至少有部分执行过程失败，但具体影响范围仍需结合完整上下文确认。",
                )
            )

        if parsed_result.level_counts.warning > 0 and not self._is_knowledge_question(question):
            findings.append(
                FindingItem(
                    title="检测到告警级别日志",
                    evidence=[f"warning 相关行数：{parsed_result.level_counts.warning}"],
                    explanation="告警信息可能指向配置偏差、资源紧张或异常前兆，但不必然意味着安全事件已经成立。",
                )
            )

        if parsed_result.possible_ips and not self._is_knowledge_question(question):
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

        if self._is_knowledge_question(question):
            summary = (
                f"已先回答与问题“{question}”相关的日志分析通用知识，并附带当前日志的基础统计作为参考。"
                f"当前日志共 {parsed_result.total_lines} 行，error 相关 {parsed_result.level_counts.error} 行，warning 相关 {parsed_result.level_counts.warning} 行。"
            )
        else:
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
