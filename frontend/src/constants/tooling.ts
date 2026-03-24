import type { HashcatAttackMode, SqliteFilterOperator } from '../types/tools'

export const TIMESTAMP_OPTIONS = [
  { value: 'auto', label: '自动识别' },
  { value: 'unix', label: 'UNIX' },
  { value: 'chrome_webkit', label: 'Chrome/WebKit' },
  { value: 'ios', label: 'iOS' },
  { value: 'dotnet_ticks', label: '.NET Ticks' },
  { value: 'windows_filetime', label: 'Windows FileTime' },
  { value: 'apple_absolute_time', label: 'Apple Absolute Time' },
]

export const TIMEZONE_OPTIONS = ['UTC', 'Asia/Shanghai', 'Asia/Tokyo', 'America/New_York', 'Europe/London']
export const HASH_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'sm3']
export const HASHCAT_ATTACK_MODES: Array<{ value: HashcatAttackMode; label: string }> = [
  { value: 0, label: '0 - 字典模式' },
  { value: 1, label: '1 - 组合模式（字典 + 字典）' },
  { value: 3, label: '3 - 掩码模式' },
  { value: 6, label: '6 - 混合模式（字典 + 掩码）' },
  { value: 7, label: '7 - 混合模式（掩码 + 字典）' },
]
export const TOOL_ORDER = ['log_parser', 'encoding_converter', 'hash_tool', 'sqlite2csv', 'timestamp_parser', 'hashcat_gui'] as const
export const DEFAULT_TOOL_ID: ToolId = 'log_parser'
export const SQLITE_FILTER_OPERATORS: Array<{ value: SqliteFilterOperator; label: string }> = [
  { value: 'contains', label: '包含' },
  { value: 'equals', label: '等于' },
  { value: 'starts_with', label: '前缀' },
  { value: 'ends_with', label: '后缀' },
  { value: 'gt', label: '大于' },
  { value: 'gte', label: '大于等于' },
  { value: 'lt', label: '小于' },
  { value: 'lte', label: '小于等于' },
  { value: 'is_null', label: '为空' },
  { value: 'not_null', label: '非空' },
]

export type ToolId = (typeof TOOL_ORDER)[number]

export interface AiToolConfig {
  supported: boolean
  title: string
  placeholder: string
  defaultInput: string
  requiresFile?: boolean
  welcome: string
}

export const AI_TOOL_CONFIG: Record<ToolId, AiToolConfig> = {
  log_parser: {
    supported: true,
    title: '日志研判助手',
    placeholder: '输入你的研判问题，例如：这份日志能支持哪些结论？有哪些证据不足？',
    defaultInput: '请只依据当前日志结果，分别给出能成立的结论、不能成立的结论和还需要补的证据。',
    requiresFile: true,
    welcome: '先上传并完成日志基础解析，再直接提问。我会结合当前日志摘要、关键片段和检索结果，给出结论、证据和证据不足点。',
  },
  encoding_converter: {
    supported: true,
    title: '编码识别助手',
    placeholder: '输入待识别的原始文本、乱码样本、Hex/Base64 片段或转义字符串。',
    defaultInput: '请先判断这段内容是否存在多层编码，区分 Base32 与 Base64，并给出可直接用于 CyberChef URL 的 recipe。',
    welcome: '直接把乱码样本、可疑编码串、Hex、Base32、Base64 或转义文本发给我。我会给出候选、置信度、分层依据和 CyberChef 配方。',
  },
  hash_tool: {
    supported: true,
    title: '文件哈希助手',
    placeholder: '例如：这些哈希值适合如何用于取证比对？当前结果能支持哪些后续动作？',
    defaultInput: '请根据当前哈希结果，说明完整性校验、样本比对和情报查询各自该怎么用。',
    welcome: '先完成哈希计算，再直接提问。我会结合当前文件名、摘要值和算法结果，整理完整性校验、样本比对和后续排查建议。',
  },
  sqlite2csv: {
    supported: true,
    title: 'SQLite 导出助手',
    placeholder: '例如：导出后我应该优先检查哪些表？这些表名可能对应什么取证线索？',
    defaultInput: '请根据当前数据库结构和预览结果，指出优先检查哪些表、哪些字段最有价值。',
    welcome: '先加载数据库结构或预览目标表，再直接提问。我会结合当前表结构、预览数据和导出结果，给出优先检查对象、关键字段和导出方向。',
  },
  timestamp_parser: {
    supported: true,
    title: '时间戳助手',
    placeholder: '例如：1710825600、132537600000000000、Chrome 时间戳原始值等',
    defaultInput: '请识别这段内容里的时间戳类型、原始时区和目标时区，并说明判断依据。',
    welcome: '把原始时间戳或混杂文本直接发过来。我会判断时间戳类型、时区、说明依据，并自动回填左侧转换表单。',
  },
  hashcat_gui: {
    supported: true,
    title: 'Hashcat 助手',
    placeholder: '例如：NTLM hash，使用 rockyou 字典；或提供掩码模式说明',
    defaultInput: '请结合当前 hash 样本和表单上下文，判断最可能的 hash_mode、attack_mode 以及可直接回填的参数。',
    welcome: '发送 hash 样本、算法线索、字典路径、掩码说明，或先上传 hash 文件。我会结合当前上下文给出 Hashcat 建议，并自动回填左侧参数。',
  },
}

export const TOOL_ICONS: Record<ToolId, string> = {
  log_parser:
    '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 5.5A1.5 1.5 0 0 1 5.5 4h8.879a1.5 1.5 0 0 1 1.06.44l3.12 3.12a1.5 1.5 0 0 1 .44 1.06V18.5A1.5 1.5 0 0 1 17.5 20h-12A1.5 1.5 0 0 1 4 18.5v-13Z" stroke="currentColor" stroke-width="1.8"/><path d="M8 11h8M8 14h5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="16.5" cy="16.5" r="2.5" stroke="currentColor" stroke-width="1.8"/><path d="m18.3 18.3 1.7 1.7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  encoding_converter:
    '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 7.5A2.5 2.5 0 0 1 6.5 5h11A2.5 2.5 0 0 1 20 7.5v9A2.5 2.5 0 0 1 17.5 19h-11A2.5 2.5 0 0 1 4 16.5v-9Z" stroke="currentColor" stroke-width="1.8"/><path d="M7.5 9.5h2.5m-1.25 0v5m4-5-2 5m4.5-5h2m-2 0 2 5m-2-5-2 5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  hash_tool:
    '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M9 4 4 9l5 5m6-10 5 5-5 5M14 7l-4 10" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  sqlite2csv:
    '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><ellipse cx="12" cy="6.5" rx="7" ry="2.5" stroke="currentColor" stroke-width="1.8"/><path d="M5 6.5v5C5 12.88 8.13 14 12 14s7-1.12 7-2.5v-5M5 11.5v6C5 18.88 8.13 20 12 20s7-1.12 7-2.5v-6" stroke="currentColor" stroke-width="1.8"/></svg>',
  timestamp_parser:
    '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="13" r="7" stroke="currentColor" stroke-width="1.8"/><path d="M12 9v4l2.5 2.5M9 3h6M12 3v3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  hashcat_gui:
    '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 5 6v5c0 4.4 2.88 8.45 7 9.72 4.12-1.27 7-5.32 7-9.72V6l-7-3Z" stroke="currentColor" stroke-width="1.8"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
}
