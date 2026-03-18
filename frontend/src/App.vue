<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'

import { getAiStatus, streamToolAi } from './api/ai'
import { getHashcatStatus, stopHashcatTask } from './api/hashcat'
import { apiBaseUrl, parseLog, searchLog, uploadLogFile } from './api/logParser'
import {
  exportSqliteTable,
  inspectSqliteDatabase,
  listTools,
  previewSqliteTable,
  runRegisteredTool,
  runRegisteredToolWithoutFile,
  uploadToolFile,
} from './api/tools'
import type {
  AiMode,
  AiStatusResponse,
  EncodingAssistResult,
  HashToolAssistResult,
  SqliteAssistResult,
  ToolAiStreamEvent,
} from './types/ai'
import type { AIAnalysisResult, FileUploadResponse, LogSearchResponse, ParsedLogResponse } from './types/logParser'
import type {
  HashToolResult,
  HashcatAIAssistResult,
  HashcatTaskStatus,
  SqliteBrowserResult,
  SqliteCsvResult,
  SqliteExportTableResult,
  SqliteFilterOperator,
  SqlitePreviewResult,
  TimestampAIAssistResult,
  TimestampParserParams,
  TimestampParserResult,
  ToolMeta,
  ToolRunResponse,
} from './types/tools'

const TIMESTAMP_OPTIONS = [
  { value: 'auto', label: '自动识别' },
  { value: 'unix', label: 'UNIX' },
  { value: 'chrome_webkit', label: 'Chrome/WebKit' },
  { value: 'ios', label: 'iOS' },
  { value: 'dotnet_ticks', label: '.NET Ticks' },
  { value: 'windows_filetime', label: 'Windows FileTime' },
  { value: 'apple_absolute_time', label: 'Apple Absolute Time' },
]

const TIMEZONE_OPTIONS = ['UTC', 'Asia/Shanghai', 'Asia/Tokyo', 'America/New_York', 'Europe/London']
const HASH_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'sm3']
const TOOL_ORDER = ['log_parser', 'encoding_converter', 'hash_tool', 'sqlite2csv', 'timestamp_parser', 'hashcat_gui'] as const
const SQLITE_FILTER_OPERATORS: Array<{ value: SqliteFilterOperator; label: string }> = [
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

type ToolId = (typeof TOOL_ORDER)[number]
type AssistantMessageStatus = 'ready' | 'streaming' | 'error'

interface AiToolConfig {
  supported: boolean
  title: string
  placeholder: string
  defaultInput: string
  requiresFile?: boolean
  welcome: string
}

interface ChatMessage {
  id: string
  toolId: ToolId
  role: 'assistant' | 'user'
  content: string
  createdAt: number
  mode?: AiMode
  source?: 'ai' | 'fallback'
  result?: Record<string, unknown> | null
  reasoning: string
  showReasoning: boolean
  progress: number
  progressLabel: string
  status: AssistantMessageStatus
  isHint?: boolean
}

const AI_TOOL_CONFIG: Record<ToolId, AiToolConfig> = {
  log_parser: {
    supported: true,
    title: '日志研判助手',
    placeholder: '输入你的研判问题，例如：这份日志能支持哪些结论？有哪些证据不足？',
    defaultInput: '请从电子取证和风险研判视角概述这份日志，并指出当前证据能支持与不能支持的结论。',
    requiresFile: true,
    welcome: '先上传并完成日志基础解析，再直接提问。我会结合当前日志摘要、关键片段和检索结果给出研判意见。',
  },
  encoding_converter: {
    supported: true,
    title: '编码识别助手',
    placeholder: '输入待识别的原始文本、乱码样本、Hex/Base64 片段或转义字符串。',
    defaultInput: '这段内容最可能是什么编码或转义格式？请给出候选、置信度和建议的 CyberChef 配方。',
    welcome: '直接把乱码样本、可疑编码串、Hex、Base64 或转义文本发给我。我会给出可能编码、置信度和 CyberChef 建议配方。',
  },
  hash_tool: {
    supported: true,
    title: '文件哈希助手',
    placeholder: '例如：这些哈希值适合如何用于取证比对？当前结果能支持哪些后续动作？',
    defaultInput: '请根据当前哈希结果说明它适合做哪些取证核验和后续比对。',
    welcome: '先完成哈希计算，再直接提问。我会结合当前文件名、摘要值和算法结果，整理取证比对、完整性校验和后续排查建议。',
  },
  sqlite2csv: {
    supported: true,
    title: 'SQLite 导出助手',
    placeholder: '例如：导出后我应该优先检查哪些表？这些表名可能对应什么取证线索？',
    defaultInput: '请根据当前导出结果说明优先检查哪些表、适合关注哪些字段。',
    welcome: '先加载数据库结构或预览目标表，再直接提问。我会结合当前表结构、预览数据和导出结果，给出优先检查对象与字段建议。',
  },
  timestamp_parser: {
    supported: true,
    title: '时间戳助手',
    placeholder: '例如：1710825600、132537600000000000、Chrome 时间戳原始值等',
    defaultInput: '请识别这段内容里的时间戳类型、原始时区和目标时区。',
    welcome: '把原始时间戳或混杂文本直接发过来。我会判断时间戳类型、时区并自动回填左侧转换表单。',
  },
  hashcat_gui: {
    supported: true,
    title: 'Hashcat 助手',
    placeholder: '例如：NTLM hash，使用 rockyou 字典；或提供掩码模式说明',
    defaultInput: '请判断这段 hash 信息最可能对应的 hash_mode、attack_mode 和建议参数。',
    welcome: '发送 hash 样本、算法线索、字典路径或掩码说明。我会给出 Hashcat 建议，并自动回填左侧参数。',
  },
}

const TOOL_ICONS: Record<ToolId, string> = {
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

const DEFAULT_TOOL_ID: ToolId = 'log_parser'

const loadingTools = ref(false)
const sidebarQuery = ref('')
const tools = ref<ToolMeta[]>([])
const globalNotice = ref('')

const activeToolId = ref<ToolId>(DEFAULT_TOOL_ID)
const leftCollapsed = ref(false)
const rightCollapsed = ref(false)

const aiMode = ref<AiMode>('chat')
const aiStatus = ref<AiStatusResponse | null>(null)
const aiBusy = ref(false)
const assistantNotice = ref('')
const assistantScrollRef = ref<HTMLElement | null>(null)

const cyberchefFrameLoaded = ref(false)
const cyberchefFrameError = ref(false)
const cyberchefReloadKey = ref(0)

const logSelectedFile = ref<File | null>(null)
const logUpload = ref<FileUploadResponse | null>(null)
const logParsed = ref<ParsedLogResponse | null>(null)
const logSearchResult = ref<LogSearchResponse | null>(null)
const logSearchQuery = ref('')
const logSearchRegex = ref(false)
const logSearchCaseSensitive = ref(false)
const logUploading = ref(false)
const logParsing = ref(false)
const logSearching = ref(false)
const logMessage = ref('')
const activeIpFilter = ref('')

const hashSelectedFile = ref<File | null>(null)
const hashUpload = ref<FileUploadResponse | null>(null)
const hashRunning = ref(false)
const hashMessage = ref('')
const hashResultRun = ref<ToolRunResponse | null>(null)
const selectedHashAlgorithms = ref<string[]>(['md5', 'sha1', 'sha256', 'sha512', 'sm3'])

const sqliteSelectedFile = ref<File | null>(null)
const sqliteUpload = ref<FileUploadResponse | null>(null)
const sqliteRunning = ref(false)
const sqliteBrowserLoading = ref(false)
const sqlitePreviewLoading = ref(false)
const sqliteExporting = ref(false)
const sqliteMessage = ref('')
const sqliteResultRun = ref<ToolRunResponse | null>(null)
const sqliteBrowser = ref<SqliteBrowserResult | null>(null)
const sqlitePreview = ref<SqlitePreviewResult | null>(null)
const sqliteTableExport = ref<SqliteExportTableResult | null>(null)
const selectedSqliteTableName = ref('')
const sqliteSelectedColumns = ref<string[]>([])
const sqlitePreviewLimit = ref(50)
const sqliteFilter = reactive<{
  column: string
  operator: SqliteFilterOperator
  value: string
}>({
  column: '',
  operator: 'contains',
  value: '',
})
const sqliteExportOptions = reactive<{
  include_header: boolean
  delimiter: ',' | ';' | '\\t' | '|'
}>({
  include_header: true,
  delimiter: ',',
})

const timestampRunning = ref(false)
const timestampMessage = ref('')
const timestampResultRun = ref<ToolRunResponse | null>(null)
const timestampForm = reactive<TimestampParserParams>({
  timestamp: '',
  timestamp_type: 'auto',
  origin_timezone: 'Asia/Shanghai',
  target_timezone: 'Asia/Shanghai',
})

const hashcatSelectedFile = ref<File | null>(null)
const hashcatUpload = ref<FileUploadResponse | null>(null)
const hashcatRunning = ref(false)
const hashcatMessage = ref('')
const hashcatStatus = ref<HashcatTaskStatus | null>(null)
const hashcatForm = reactive({
  hash_mode: 0,
  attack_mode: 0 as 0 | 3,
  wordlist_path: '',
  mask: '',
  extra_args_text: '',
  session_name: '',
})

const aiInputs = reactive<Record<ToolId, string>>({
  log_parser: AI_TOOL_CONFIG.log_parser.defaultInput,
  encoding_converter: AI_TOOL_CONFIG.encoding_converter.defaultInput,
  hash_tool: '',
  sqlite2csv: '',
  timestamp_parser: AI_TOOL_CONFIG.timestamp_parser.defaultInput,
  hashcat_gui: AI_TOOL_CONFIG.hashcat_gui.defaultInput,
})

const chatThreads = reactive<Record<ToolId, ChatMessage[]>>({
  log_parser: [],
  encoding_converter: [],
  hash_tool: [],
  sqlite2csv: [],
  timestamp_parser: [],
  hashcat_gui: [],
})

let hashcatTimer: number | null = null
let messageSeed = 0
let scrollFrame: number | null = null

const shellStyle = computed(() => ({
  '--left-rail-width': leftCollapsed.value ? '52px' : '280px',
  '--right-rail-width': rightCollapsed.value ? '46px' : '392px',
}))

const filteredTools = computed(() => {
  const keyword = sidebarQuery.value.trim().toLowerCase()
  const sorted = [...tools.value].sort((left, right) => getToolOrder(left.tool_id) - getToolOrder(right.tool_id))
  if (!keyword) {
    return sorted
  }
  return sorted.filter((tool) => tool.name.toLowerCase().includes(keyword) || tool.tool_id.toLowerCase().includes(keyword))
})

const activeTool = computed(() => tools.value.find((tool) => tool.tool_id === activeToolId.value) ?? null)
const activeAiConfig = computed(() => AI_TOOL_CONFIG[activeToolId.value])
const currentAiInput = computed({
  get: () => aiInputs[activeToolId.value],
  set: (value: string) => {
    aiInputs[activeToolId.value] = value
  },
})
const currentThread = computed(() => chatThreads[activeToolId.value])
const currentAiModelLabel = computed(() =>
  aiMode.value === 'reasoner' ? aiStatus.value?.reasoner_model || 'Reasoner' : aiStatus.value?.chat_model || 'Chat',
)
const hashDisplayName = computed(() => hashUpload.value?.original_name || hashToolResult.value?.file_name || '--')
const logSummaryCards = computed(() => {
  if (!logParsed.value) return []
  return [
    { label: '总行数', value: String(logParsed.value.total_lines) },
    { label: 'Error', value: String(logParsed.value.level_counts.error) },
    { label: 'Warning', value: String(logParsed.value.level_counts.warning) },
    { label: 'Info', value: String(logParsed.value.level_counts.info) },
    { label: '时间戳', value: logParsed.value.has_timestamp ? '已检测' : '未检测' },
    { label: 'IP 数量', value: String(logParsed.value.ip_stats.length) },
  ]
})
const previewTitle = computed(() => {
  if (activeIpFilter.value) return `IP 筛选预览：${activeIpFilter.value}`
  if (logSearchResult.value) return `搜索结果预览：${logSearchResult.value.total_matches} 条`
  return '日志预览'
})
const previewContent = computed(() => {
  if (logSearchResult.value) {
    return logSearchResult.value.matches.map((match) => `${String(match.line_number).padStart(5, '0')} | ${match.content}`)
  }
  return logParsed.value?.preview_lines ?? []
})
const hashToolResult = computed(() => (hashResultRun.value?.result ?? null) as HashToolResult | null)
const hashDisplayItems = computed(() => {
  if (!hashToolResult.value) {
    return []
  }
  return hashToolResult.value.algorithms.map((algorithm) => ({
    algorithm,
    label: algorithm.toUpperCase(),
    value: hashToolResult.value?.hashes[algorithm] || '',
  }))
})
const sqliteResult = computed(() => (sqliteResultRun.value?.result ?? null) as SqliteCsvResult | null)
const timestampResult = computed(() => (timestampResultRun.value?.result ?? null) as TimestampParserResult | null)
const cyberchefBaseUrl = computed(() => '/cyberchef/CyberChef.html')
const cyberchefUrl = computed(() => `${cyberchefBaseUrl.value}?embedded=1&reload=${cyberchefReloadKey.value}`)
const selectedSqliteTable = computed(() =>
  sqliteBrowser.value?.tables.find((table) => table.table_name === selectedSqliteTableName.value) ?? null,
)

function getToolOrder(toolId: string): number {
  const index = TOOL_ORDER.indexOf(toolId as ToolId)
  return index === -1 ? TOOL_ORDER.length + 1 : index
}

function createMessageId(): string {
  messageSeed += 1
  return `msg-${messageSeed}`
}

function toolBadge(tool: ToolMeta): string {
  const parts = tool.tool_id.split('_').filter(Boolean)
  return (parts[0]?.[0] || tool.name[0] || 'T').toUpperCase()
}

function toolIcon(toolId: string): string {
  return TOOL_ICONS[normalizeToolId(toolId)]
}

function formatMessageTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
  })
}

function sanitizeDisplayText(value: string | null | undefined): string {
  const text = (value || '')
    .replace(/\r\n/g, '\n')
    .replace(/^\uFEFF/, '')
    .replace(/\u200B/g, '')
    .replace(/(^|\n)\s*\d+\.\s*(?=\n|$)/g, '$1')
  const cleaned = text
    .split('\n')
    .filter((line, index, lines) => {
      const trimmed = line.trim()
      if (!trimmed) {
        const prev = lines[index - 1]?.trim()
        return Boolean(prev)
      }
      return !/^\d+\.\s*$/.test(trimmed)
    })
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
  return cleaned
}

function normalizeStreamingText(value: string | null | undefined): string {
  return (value || '').replace(/\r\n/g, '\n').replace(/^\uFEFF/, '').replace(/\u200B/g, '')
}

function humanizeStreamingText(rawContent: string): string {
  const decoded = normalizeStreamingText(rawContent)
    .replace(/\\"/g, '"')
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')

  const loose = decoded
    .replace(/\\u[\dA-Fa-f]{4}/g, ' ')
    .replace(/[{}[\]"]/g, ' ')
    .replace(/\b(?:summary|explanation|reasoning|findings|recommendations|timeline_summary|risk_level)\b\s*:/g, ' ')
    .replace(/[,:]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()

  return sanitizeDisplayText(loose || decoded)
}

function fragmentTone(fragment: { title: string; snippet: string[] }): 'error' | 'warning' | 'neutral' {
  const title = fragment.title.toLowerCase()
  const snippet = fragment.snippet.join('\n').toLowerCase()
  const source = `${title}\n${snippet}`
  if (/(error|exception|fatal|failed|traceback|denied|unauthorized)/.test(source)) {
    return 'error'
  }
  if (/(warning|warn|deprecated|retry|timeout)/.test(source)) {
    return 'warning'
  }
  return 'neutral'
}

function riskBadgeClass(level: string): string {
  if (level === 'high') return 'badge-danger'
  if (level === 'medium') return 'badge-warning'
  if (level === 'low') return 'badge-success'
  return 'badge-neutral'
}

function getErrorMessage(error: unknown, fallback: string): string {
  const maybeError = error as { response?: { data?: { detail?: string } }; message?: string }
  return maybeError?.response?.data?.detail || maybeError?.message || fallback
}

function parseExtraArgs(value: string): string[] {
  return value
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function resolveStorageUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) return path
  const backendBase = /^https?:\/\//i.test(apiBaseUrl)
    ? apiBaseUrl
    : new URL(apiBaseUrl, window.location.origin).toString()
  return new URL(path, backendBase).toString()
}

function triggerBrowserDownload(path: string, fileName?: string): void {
  const href = resolveStorageUrl(path)
  const link = document.createElement('a')
  link.href = href
  if (fileName) {
    link.download = fileName
  }
  link.rel = 'noreferrer'
  document.body.appendChild(link)
  link.click()
  link.remove()
}

function toggleLeftSidebar(): void {
  leftCollapsed.value = !leftCollapsed.value
}

function toggleRightSidebar(): void {
  rightCollapsed.value = !rightCollapsed.value
  if (!rightCollapsed.value) {
    void scrollChatToBottom()
  }
}

function pickActiveTool(toolId: string): void {
  activeToolId.value = normalizeToolId(toolId)
  assistantNotice.value = ''
  globalNotice.value = ''
}

function normalizeToolId(toolId: string): ToolId {
  return (TOOL_ORDER.includes(toolId as ToolId) ? toolId : DEFAULT_TOOL_ID) as ToolId
}

function buildWelcomeMessage(toolId: ToolId): ChatMessage {
  return {
    id: createMessageId(),
    toolId,
    role: 'assistant',
    content: sanitizeDisplayText(AI_TOOL_CONFIG[toolId].welcome),
    createdAt: Date.now(),
    reasoning: '',
    showReasoning: false,
    progress: 100,
    progressLabel: '已就绪',
    status: 'ready',
    isHint: true,
    result: null,
  }
}

function ensureThread(toolId: ToolId): void {
  if (!chatThreads[toolId].length) {
    chatThreads[toolId].push(buildWelcomeMessage(toolId))
  }
}

function pushAssistantNotice(message: string): void {
  assistantNotice.value = message
}

function sqliteFiltersPayload(): Array<{ column: string; operator: SqliteFilterOperator; value?: string | null }> {
  if (!sqliteFilter.column) {
    return []
  }
  return [
    {
      column: sqliteFilter.column,
      operator: sqliteFilter.operator,
      value: sqliteFilter.value || null,
    },
  ]
}

function summarizeToolResult(toolId: ToolId, result: Record<string, unknown>): string {
  if (toolId === 'log_parser') {
    return sanitizeDisplayText((result as unknown as AIAnalysisResult).summary || '日志研判已完成。')
  }
  if (toolId === 'hash_tool') {
    return sanitizeDisplayText((result as unknown as HashToolAssistResult).summary || '哈希结果分析已完成。')
  }
  if (toolId === 'sqlite2csv') {
    return sanitizeDisplayText((result as unknown as SqliteAssistResult).summary || 'SQLite 分析已完成。')
  }
  if (toolId === 'timestamp_parser') {
    return sanitizeDisplayText((result as unknown as TimestampAIAssistResult).explanation || '时间戳识别已完成。')
  }
  if (toolId === 'hashcat_gui') {
    return sanitizeDisplayText((result as unknown as HashcatAIAssistResult).explanation || 'Hashcat 配置建议已生成。')
  }
  if (toolId === 'encoding_converter') {
    return sanitizeDisplayText((result as unknown as EncodingAssistResult).explanation || '编码识别已完成。')
  }
  return '处理完成。'
}

function buildLocalToolReply(toolId: ToolId, userInput: string): string {
  const normalizedQuestion = userInput.trim() || '当前结果该如何使用？'

  if (toolId === 'hash_tool') {
    if (!hashToolResult.value) {
      return '当前还没有哈希结果。先上传文件并完成计算，然后我可以结合 MD5、SHA1、SHA256、SHA512 的结果说明如何用于完整性校验、情报检索和证据留存。'
    }

    const algorithms = hashToolResult.value.algorithms.map((item) => item.toUpperCase()).join('、')
    return [
      `已基于文件“${hashToolResult.value.file_name}”的哈希结果回答你的问题：“${normalizedQuestion}”。`,
      `当前已生成 ${algorithms} 摘要，可优先把 SHA256 作为主校验值，MD5/SHA1 作为兼容性补充。`,
      '如果要做取证核验，建议先固定保存摘要值，再和样本库、威胁情报平台或历史证据链做比对。',
      '如果你想让我进一步帮你判断用途，可以继续追问例如“这个结果更适合做完整性校验还是样本碰撞排查”。',
    ].join('\n')
  }

  if (toolId === 'sqlite2csv') {
    if (!sqliteResult.value) {
      if (!sqliteBrowser.value) {
        return '当前还没有 SQLite 数据库浏览结果。先上传数据库并加载结构，然后我可以结合表名、字段和预览数据帮助你判断优先查看哪些表。'
      }
    }

    const sourceTables = sqliteBrowser.value?.tables ?? sqliteResult.value?.tables ?? []
    const previewTables = sourceTables.slice(0, 5).map((table) => table.table_name).join('、') || '暂无表信息'
    const activeTableHint = selectedSqliteTable.value
      ? `当前已选中表“${selectedSqliteTable.value.table_name}”，字段数 ${selectedSqliteTable.value.columns.length}。`
      : '当前还没有选中具体表。'
    return [
      `已基于数据库“${sqliteBrowser.value?.database_name || sqliteResult.value?.database_name || '当前数据库'}”的结果回答你的问题：“${normalizedQuestion}”。`,
      `当前共识别 ${sourceTables.length} 张表，建议优先查看：${previewTables}。`,
      activeTableHint,
      '通常可以先按表名中的 message、user、login、history、cache、event、record 等关键词筛查，再结合行数和字段名定位高价值数据。',
      '如果你继续问某张表可能存什么内容，我会按现有表名和列名继续做本地整理说明。',
    ].join('\n')
  }

  return '当前工具未接入远程 AI，我已切换为本地聊天辅助。你可以继续提问，我会根据现有结果给出可执行建议。'
}

function applyAiResult(toolId: ToolId, result: Record<string, unknown>): void {
  if (toolId === 'timestamp_parser') {
    const payload = result as unknown as TimestampAIAssistResult
    timestampForm.timestamp = payload.timestamp
    timestampForm.timestamp_type = payload.timestamp_type
    timestampForm.origin_timezone = payload.origin_timezone
    timestampForm.target_timezone = payload.target_timezone
    timestampMessage.value = 'AI 建议已回填到时间戳表单。'
  }

  if (toolId === 'hashcat_gui') {
    const payload = result as unknown as HashcatAIAssistResult
    hashcatForm.hash_mode = payload.hash_mode
    hashcatForm.attack_mode = payload.attack_mode
    hashcatForm.wordlist_path = payload.wordlist_path ?? ''
    hashcatForm.mask = payload.mask ?? ''
    hashcatForm.session_name = payload.session_name ?? ''
    hashcatForm.extra_args_text = payload.extra_args.join(' ')
    hashcatMessage.value = 'AI 建议已回填到 Hashcat 表单。'
  }
}

function currentAiFileId(): string | null {
  if (activeToolId.value === 'log_parser') return logUpload.value?.file_id ?? null
  if (activeToolId.value === 'hash_tool') return hashUpload.value?.file_id ?? null
  if (activeToolId.value === 'sqlite2csv') return sqliteUpload.value?.file_id ?? null
  if (activeToolId.value === 'hashcat_gui') return hashcatUpload.value?.file_id ?? null
  return null
}

function currentAiContext(toolId: ToolId): Record<string, unknown> {
  if (toolId === 'hash_tool') {
    return {
      hash_result: hashToolResult.value,
      upload: hashUpload.value
        ? {
            file_id: hashUpload.value.file_id,
            original_name: hashUpload.value.original_name,
            created_at: hashUpload.value.created_at,
          }
        : null,
    }
  }

  if (toolId === 'sqlite2csv') {
    return {
      browser: sqliteBrowser.value
        ? {
            database_name: sqliteBrowser.value.database_name,
            table_count: sqliteBrowser.value.tables.length,
            tables: sqliteBrowser.value.tables.map((table) => ({
              table_name: table.table_name,
              row_count: table.row_count,
              columns: table.columns,
              schema_sql: table.schema_sql,
            })),
          }
        : null,
      selected_table: selectedSqliteTable.value,
      preview: sqlitePreview.value
        ? {
            table_name: sqlitePreview.value.table_name,
            selected_columns: sqlitePreview.value.selected_columns,
            total_rows: sqlitePreview.value.total_rows,
            returned_rows: sqlitePreview.value.returned_rows,
            rows: sqlitePreview.value.rows.slice(0, 10),
          }
        : null,
      table_export: sqliteTableExport.value,
      full_export: sqliteResult.value,
      upload: sqliteUpload.value
        ? {
            file_id: sqliteUpload.value.file_id,
            original_name: sqliteUpload.value.original_name,
            created_at: sqliteUpload.value.created_at,
          }
        : null,
    }
  }

  return {}
}

async function scrollChatToBottom(): Promise<void> {
  await nextTick()
  const node = assistantScrollRef.value
  if (!node) return
  node.scrollTop = node.scrollHeight
}

function scheduleScrollChatToBottom(): void {
  if (scrollFrame !== null) {
    return
  }
  scrollFrame = window.requestAnimationFrame(() => {
    scrollFrame = null
    void scrollChatToBottom()
  })
}

function createUserMessage(toolId: ToolId, content: string): ChatMessage {
  return {
    id: createMessageId(),
    toolId,
    role: 'user',
    content: sanitizeDisplayText(content),
    createdAt: Date.now(),
    reasoning: '',
    showReasoning: false,
    progress: 100,
    progressLabel: '已发送',
    status: 'ready',
    result: null,
  }
}

function createAssistantMessage(toolId: ToolId, mode: AiMode): ChatMessage {
  return {
    id: createMessageId(),
    toolId,
    role: 'assistant',
    content: '',
    createdAt: Date.now(),
    mode,
    reasoning: '',
    showReasoning: mode === 'reasoner',
    progress: mode === 'reasoner' ? 12 : 20,
    progressLabel: mode === 'reasoner' ? '已提交推理请求' : '已提交请求',
    status: 'streaming',
    result: null,
  }
}

function handleAiComposerKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Enter' || event.shiftKey) {
    return
  }
  event.preventDefault()
  void runAiForActiveTool()
}

async function loadTools(): Promise<void> {
  loadingTools.value = true
  try {
    tools.value = await listTools()
    const activeExists = tools.value.some((tool) => tool.tool_id === activeToolId.value)
    if (!activeExists && tools.value[0]) {
      activeToolId.value = normalizeToolId(tools.value[0].tool_id)
    }
  } catch (error) {
    globalNotice.value = getErrorMessage(error, '工具列表加载失败。')
  } finally {
    loadingTools.value = false
  }
}

async function loadAiMeta(): Promise<void> {
  try {
    aiStatus.value = await getAiStatus()
  } catch {
    aiStatus.value = { configured: false, chat_model: null, reasoner_model: null }
  }
}

async function refreshHashcatStatus(): Promise<void> {
  const hashcatTool = tools.value.find((tool) => tool.tool_id === 'hashcat_gui') ?? null
  if (hashcatTool && !hashcatTool.enabled) {
    hashcatStatus.value = {
      enabled: false,
      disabled_title: hashcatTool.disabled_title,
      disabled_message: hashcatTool.disabled_message,
      configured: false,
      binary_path: null,
      running: false,
      task_id: null,
      pid: null,
      command: [],
      started_at: null,
      finished_at: null,
      exit_code: null,
      hash_file: null,
      output_tail: [],
    }
    return
  }

  try {
    hashcatStatus.value = await getHashcatStatus()
  } catch (error) {
    hashcatMessage.value = getErrorMessage(error, 'Hashcat 状态获取失败。')
  }
}

function handleFileSelection(event: Event, setter: (file: File | null) => void): void {
  const target = event.target as HTMLInputElement
  setter(target.files?.[0] ?? null)
}

function setLogSelectedFile(file: File | null): void {
  logSelectedFile.value = file
}

function setHashSelectedFile(file: File | null): void {
  hashSelectedFile.value = file
}

function setSqliteSelectedFile(file: File | null): void {
  sqliteSelectedFile.value = file
}

function setHashcatSelectedFile(file: File | null): void {
  hashcatSelectedFile.value = file
}

async function uploadLog(): Promise<void> {
  if (!logSelectedFile.value) {
    logMessage.value = '请先选择日志文件。'
    return
  }
  logUploading.value = true
  try {
    logUpload.value = await uploadLogFile(logSelectedFile.value)
    logParsed.value = null
    logSearchResult.value = null
    logMessage.value = '日志上传完成。'
  } catch (error) {
    logMessage.value = getErrorMessage(error, '日志上传失败。')
  } finally {
    logUploading.value = false
  }
}

async function runLogParse(): Promise<void> {
  if (!logUpload.value) {
    logMessage.value = '请先上传日志文件。'
    return
  }
  logParsing.value = true
  try {
    logParsed.value = await parseLog(logUpload.value.file_id)
    logSearchResult.value = null
    activeIpFilter.value = ''
    logMessage.value = '基础解析完成。'
  } catch (error) {
    logMessage.value = getErrorMessage(error, '基础解析失败。')
  } finally {
    logParsing.value = false
  }
}

async function runLogSearch(queryOverride?: string): Promise<void> {
  if (!logUpload.value) {
    logMessage.value = '请先上传日志文件。'
    return
  }
  const query = (queryOverride ?? logSearchQuery.value).trim()
  if (!query) {
    logMessage.value = '请输入搜索内容。'
    return
  }
  logSearching.value = true
  try {
    logSearchQuery.value = query
    activeIpFilter.value = queryOverride ?? ''
    logSearchResult.value = await searchLog(logUpload.value.file_id, {
      query,
      use_regex: logSearchRegex.value,
      case_sensitive: logSearchCaseSensitive.value,
      limit: 200,
    })
    logMessage.value = '搜索完成。'
  } catch (error) {
    logMessage.value = getErrorMessage(error, '日志搜索失败。')
  } finally {
    logSearching.value = false
  }
}

function clearLogSearch(): void {
  logSearchResult.value = null
  activeIpFilter.value = ''
  logSearchQuery.value = ''
}

async function uploadSharedToolFile(
  fileRef: { value: File | null },
  uploadRef: { value: FileUploadResponse | null },
  messageRef: { value: string },
  toolId: ToolId,
): Promise<void> {
  if (!fileRef.value) {
    messageRef.value = '请先选择文件。'
    return
  }
  try {
    uploadRef.value = await uploadToolFile(fileRef.value, toolId)
    messageRef.value = '文件上传完成。'
  } catch (error) {
    messageRef.value = getErrorMessage(error, '文件上传失败。')
  }
}

const uploadHashToolFile = () => uploadSharedToolFile(hashSelectedFile, hashUpload, hashMessage, 'hash_tool')
const uploadHashcatFile = () => uploadSharedToolFile(hashcatSelectedFile, hashcatUpload, hashcatMessage, 'hashcat_gui')

async function uploadSqliteFile(): Promise<void> {
  await uploadSharedToolFile(sqliteSelectedFile, sqliteUpload, sqliteMessage, 'sqlite2csv')
  sqliteBrowser.value = null
  sqlitePreview.value = null
  sqliteTableExport.value = null
  selectedSqliteTableName.value = ''
  sqliteSelectedColumns.value = []
  sqliteFilter.column = ''
  sqliteFilter.value = ''
  if (sqliteUpload.value) {
    await loadSqliteBrowser()
  }
}

async function loadSqliteBrowser(): Promise<void> {
  if (!sqliteUpload.value) {
    sqliteMessage.value = '请先上传 SQLite 文件。'
    return
  }
  sqliteBrowserLoading.value = true
  try {
    sqliteBrowser.value = await inspectSqliteDatabase(sqliteUpload.value.file_id)
    sqliteResultRun.value = null
    sqliteTableExport.value = null
    if (sqliteBrowser.value.tables.length > 0) {
      await selectSqliteTable(sqliteBrowser.value.tables[0].table_name)
    } else {
      sqlitePreview.value = null
    }
    sqliteMessage.value = '数据库结构加载完成。'
  } catch (error) {
    sqliteMessage.value = getErrorMessage(error, '数据库结构加载失败。')
  } finally {
    sqliteBrowserLoading.value = false
  }
}

async function selectSqliteTable(tableName: string): Promise<void> {
  selectedSqliteTableName.value = tableName
  const table = sqliteBrowser.value?.tables.find((item) => item.table_name === tableName) ?? null
  sqliteSelectedColumns.value = table?.columns.map((column) => column.name) ?? []
  sqliteFilter.column = table?.columns[0]?.name ?? ''
  sqliteFilter.operator = 'contains'
  sqliteFilter.value = ''
  sqliteTableExport.value = null
  await previewCurrentSqliteTable()
}

async function previewCurrentSqliteTable(): Promise<void> {
  if (!sqliteUpload.value || !selectedSqliteTableName.value) {
    sqliteMessage.value = '请先加载数据库并选择目标表。'
    return
  }
  if (!sqliteSelectedColumns.value.length) {
    sqliteMessage.value = '请至少选择一个字段后再预览。'
    return
  }
  sqlitePreviewLoading.value = true
  try {
    sqlitePreview.value = await previewSqliteTable(sqliteUpload.value.file_id, {
      table_name: selectedSqliteTableName.value,
      selected_columns: sqliteSelectedColumns.value,
      filters: sqliteFiltersPayload(),
      limit: sqlitePreviewLimit.value,
      offset: 0,
    })
    sqliteMessage.value = '数据预览已刷新。'
  } catch (error) {
    sqliteMessage.value = getErrorMessage(error, '数据预览失败。')
  } finally {
    sqlitePreviewLoading.value = false
  }
}

async function exportCurrentSqliteTable(): Promise<void> {
  if (!sqliteUpload.value || !selectedSqliteTableName.value) {
    sqliteMessage.value = '请先加载数据库并选择目标表。'
    return
  }
  if (!sqliteSelectedColumns.value.length) {
    sqliteMessage.value = '请至少选择一个字段后再导出。'
    return
  }
  sqliteExporting.value = true
  try {
    sqliteTableExport.value = await exportSqliteTable(sqliteUpload.value.file_id, {
      table_name: selectedSqliteTableName.value,
      selected_columns: sqliteSelectedColumns.value,
      filters: sqliteFiltersPayload(),
      include_header: sqliteExportOptions.include_header,
      delimiter: sqliteExportOptions.delimiter,
    })
    triggerBrowserDownload(sqliteTableExport.value.csv_url, sqliteTableExport.value.csv_name)
    sqliteMessage.value = '当前表 CSV 已开始下载。'
  } catch (error) {
    sqliteMessage.value = getErrorMessage(error, '导出当前表失败。')
  } finally {
    sqliteExporting.value = false
  }
}

async function runHashTool(): Promise<void> {
  if (!hashUpload.value) {
    hashMessage.value = '请先上传目标文件。'
    return
  }
  hashRunning.value = true
  try {
    hashResultRun.value = await runRegisteredTool('hash_tool', hashUpload.value.file_id, { algorithms: selectedHashAlgorithms.value })
    hashMessage.value = '哈希计算完成。'
  } catch (error) {
    hashMessage.value = getErrorMessage(error, '哈希计算失败。')
  } finally {
    hashRunning.value = false
  }
}

async function runSqliteExport(): Promise<void> {
  if (!sqliteUpload.value) {
    sqliteMessage.value = '请先上传 SQLite 文件。'
    return
  }
  sqliteRunning.value = true
  try {
    sqliteResultRun.value = await runRegisteredTool('sqlite2csv', sqliteUpload.value.file_id)
    const zipUrl = (sqliteResultRun.value.result.zip_url as string | undefined) || ''
    const zipName = (sqliteResultRun.value.result.zip_name as string | undefined) || undefined
    if (zipUrl) {
      triggerBrowserDownload(zipUrl, zipName)
    }
    sqliteMessage.value = 'SQLite 导出包已开始下载。'
  } catch (error) {
    sqliteMessage.value = getErrorMessage(error, 'SQLite 导出失败。')
  } finally {
    sqliteRunning.value = false
  }
}

async function runTimestampParser(): Promise<void> {
  timestampRunning.value = true
  try {
    timestampResultRun.value = await runRegisteredToolWithoutFile('timestamp_parser', { ...timestampForm })
    timestampMessage.value = '时间戳转换完成。'
  } catch (error) {
    timestampMessage.value = getErrorMessage(error, '时间戳转换失败。')
  } finally {
    timestampRunning.value = false
  }
}

async function runHashcatTask(): Promise<void> {
  if (!hashcatUpload.value) {
    hashcatMessage.value = '请先上传 hash 文件。'
    return
  }
  hashcatRunning.value = true
  try {
    await runRegisteredTool('hashcat_gui', hashcatUpload.value.file_id, {
      hash_mode: Number(hashcatForm.hash_mode),
      attack_mode: Number(hashcatForm.attack_mode),
      wordlist_path: hashcatForm.wordlist_path || undefined,
      mask: hashcatForm.mask || undefined,
      session_name: hashcatForm.session_name || undefined,
      extra_args: parseExtraArgs(hashcatForm.extra_args_text),
    })
    await refreshHashcatStatus()
    hashcatMessage.value = 'Hashcat 任务已启动。'
  } catch (error) {
    hashcatMessage.value = getErrorMessage(error, 'Hashcat 启动失败。')
  } finally {
    hashcatRunning.value = false
  }
}

async function stopHashcat(): Promise<void> {
  try {
    hashcatStatus.value = await stopHashcatTask()
    hashcatMessage.value = 'Hashcat 任务已停止。'
  } catch (error) {
    hashcatMessage.value = getErrorMessage(error, '停止 Hashcat 任务失败。')
  }
}

function getLogResult(message: ChatMessage): AIAnalysisResult | null {
  if (message.toolId !== 'log_parser' || !message.result) return null
  return message.result as unknown as AIAnalysisResult
}

function getTimestampResult(message: ChatMessage): TimestampAIAssistResult | null {
  if (message.toolId !== 'timestamp_parser' || !message.result) return null
  return message.result as unknown as TimestampAIAssistResult
}

function getHashToolAiResult(message: ChatMessage): HashToolAssistResult | null {
  if (message.toolId !== 'hash_tool' || !message.result) return null
  return message.result as unknown as HashToolAssistResult
}

function getSqliteAiResult(message: ChatMessage): SqliteAssistResult | null {
  if (message.toolId !== 'sqlite2csv' || !message.result) return null
  return message.result as unknown as SqliteAssistResult
}

function getHashcatAiResult(message: ChatMessage): HashcatAIAssistResult | null {
  if (message.toolId !== 'hashcat_gui' || !message.result) return null
  return message.result as unknown as HashcatAIAssistResult
}

function getEncodingResult(message: ChatMessage): EncodingAssistResult | null {
  if (message.toolId !== 'encoding_converter' || !message.result) return null
  return message.result as unknown as EncodingAssistResult
}

function reloadCyberChef(): void {
  cyberchefFrameLoaded.value = false
  cyberchefFrameError.value = false
  cyberchefReloadKey.value += 1
}

function handleCyberChefLoad(): void {
  cyberchefFrameLoaded.value = true
  cyberchefFrameError.value = false
}

function handleCyberChefError(): void {
  cyberchefFrameLoaded.value = false
  cyberchefFrameError.value = true
}

function shouldRefreshHashcatStatus(): boolean {
  const hashcatTool = tools.value.find((tool) => tool.tool_id === 'hashcat_gui')
  if (!hashcatTool?.enabled) {
    return false
  }
  return activeToolId.value === 'hashcat_gui' || Boolean(hashcatStatus.value?.running)
}

async function runAiForActiveTool(): Promise<void> {
  const toolId = activeToolId.value
  const config = activeAiConfig.value

  ensureThread(toolId)
  assistantNotice.value = ''

  const userInput = currentAiInput.value.trim()
  if (!userInput) {
    pushAssistantNotice('请输入内容后再发送。')
    return
  }

  const fileId = currentAiFileId()
  if (config.requiresFile && !fileId) {
    pushAssistantNotice('当前工具需要先上传文件并完成基础准备。')
    return
  }

  const thread = chatThreads[toolId]
  const userMessage = createUserMessage(toolId, userInput)
  const assistantMessage = createAssistantMessage(toolId, aiMode.value)
  thread.push(userMessage, assistantMessage)
  aiInputs[toolId] = ''
  aiBusy.value = true
  scheduleScrollChatToBottom()

  try {
    if (!config.supported) {
      assistantMessage.status = 'ready'
      assistantMessage.source = 'fallback'
      assistantMessage.content = buildLocalToolReply(toolId, userInput)
      assistantMessage.progress = 100
      assistantMessage.progressLabel = '本地辅助已完成'
      return
    }

    const payload = {
      tool_id: toolId,
      user_input: userInput,
      mode: aiMode.value,
      file_id: fileId,
      context: currentAiContext(toolId),
    }

    let receivedFinal = false
    let pendingReasoning = ''
    let pendingContent = ''
    let pendingContentPreview = ''
    let flushTimer: number | null = null
    let contentFlushTimer: number | null = null

    const flushReasoning = () => {
      if (!pendingReasoning) {
        return
      }
      assistantMessage.reasoning = normalizeStreamingText(pendingReasoning)
      pendingReasoning = ''
      assistantMessage.showReasoning = aiMode.value === 'reasoner'
      scheduleScrollChatToBottom()
    }

    const queueReasoning = (event: Extract<ToolAiStreamEvent, { type: 'reasoning' }>) => {
      pendingReasoning = event.full_text || `${pendingReasoning}${event.delta}`
      if (flushTimer !== null) {
        return
      }
      flushTimer = window.setTimeout(() => {
        flushTimer = null
        flushReasoning()
      }, 80)
    }

    const flushContent = () => {
      if (!pendingContent) {
        return
      }
      assistantMessage.content = sanitizeDisplayText(pendingContentPreview || humanizeStreamingText(pendingContent))
      scheduleScrollChatToBottom()
    }

    const queueContent = (event: Extract<ToolAiStreamEvent, { type: 'content' }>) => {
      pendingContent = event.full_text || `${pendingContent}${event.delta}`
      pendingContentPreview = event.preview || ''
      if (contentFlushTimer !== null) {
        return
      }
      contentFlushTimer = window.setTimeout(() => {
        contentFlushTimer = null
        flushContent()
      }, 80)
    }

    await streamToolAi(payload, {
      onEvent: (event: ToolAiStreamEvent) => {
        if (event.type === 'reasoning') {
          if (aiMode.value === 'reasoner') {
            queueReasoning(event)
          }
          return
        }
        if (event.type === 'content') {
          queueContent(event)
          return
        }
        if (event.type === 'final') {
          receivedFinal = true
          if (flushTimer !== null) {
            window.clearTimeout(flushTimer)
            flushTimer = null
          }
          if (contentFlushTimer !== null) {
            window.clearTimeout(contentFlushTimer)
            contentFlushTimer = null
          }
          flushReasoning()
          flushContent()
          assistantMessage.status = 'ready'
          assistantMessage.source = event.source
          assistantMessage.mode = event.mode
          assistantMessage.result = event.result
          assistantMessage.reasoning = sanitizeDisplayText(event.reasoning || assistantMessage.reasoning)
          assistantMessage.content = summarizeToolResult(toolId, event.result)
          applyAiResult(toolId, event.result)
          scheduleScrollChatToBottom()
        }
      },
    })
    if (!receivedFinal) {
      throw new Error('AI 流式调用未返回最终结果。')
    }
  } catch (error) {
    assistantMessage.status = 'error'
    assistantMessage.content = sanitizeDisplayText(getErrorMessage(error, 'AI 调用失败。'))
  } finally {
    aiBusy.value = false
    scheduleScrollChatToBottom()
  }
}

watch(
  activeToolId,
  (toolId) => {
    ensureThread(toolId)
    assistantNotice.value = ''
    if (toolId === 'encoding_converter') {
      reloadCyberChef()
    }
    if (toolId === 'hashcat_gui') {
      const hashcatTool = tools.value.find((tool) => tool.tool_id === 'hashcat_gui')
      if (hashcatTool?.enabled) {
        void refreshHashcatStatus()
      }
    }
    scheduleScrollChatToBottom()
  },
  { immediate: true },
)

onMounted(async () => {
  await Promise.all([loadTools(), loadAiMeta()])
  ensureThread(activeToolId.value)
  hashcatTimer = window.setInterval(() => {
    if (shouldRefreshHashcatStatus()) {
      void refreshHashcatStatus()
    }
  }, 5000)
  scheduleScrollChatToBottom()
})

onBeforeUnmount(() => {
  if (hashcatTimer !== null) {
    window.clearInterval(hashcatTimer)
  }
  if (scrollFrame !== null) {
    window.cancelAnimationFrame(scrollFrame)
    scrollFrame = null
  }
})
</script>

<template>
  <div class="toolbox-shell" :style="shellStyle">
    <aside class="toolbox-sidebar" :class="{ collapsed: leftCollapsed }">
      <button type="button" class="rail-toggle rail-toggle-left" :aria-label="leftCollapsed ? '展开工具栏' : '收起工具栏'" @click="toggleLeftSidebar">
        {{ leftCollapsed ? '›' : '‹' }}
      </button>

      <div v-if="!leftCollapsed" class="brand-block">
        <img class="brand-avatar" src="/avatar.png" alt="智能电子取证工具平台" />
        <div class="brand-copy">
          <div class="brand-title">智能电子取证工具平台</div>
          <div class="brand-subtitle">Forensics Workspace</div>
        </div>
      </div>

      <div v-if="!leftCollapsed" class="sidebar-panel">
        <div class="sidebar-heading">工具筛选</div>
        <input v-model="sidebarQuery" class="form-control toolbox-filter" type="text" placeholder="搜索工具" />
      </div>

      <div v-if="!leftCollapsed" class="sidebar-panel grow">
        <div v-if="!leftCollapsed" class="sidebar-heading">工具列表</div>
        <div v-if="loadingTools" class="sidebar-empty">正在加载工具...</div>
        <div v-else-if="!filteredTools.length" class="sidebar-empty">没有匹配的工具。</div>

        <div class="tool-nav-list">
          <button
            v-for="tool in filteredTools"
            :key="tool.tool_id"
            type="button"
            class="tool-nav-item"
            :class="{ active: activeToolId === tool.tool_id, disabled: !tool.enabled, compact: leftCollapsed }"
            :title="leftCollapsed ? `${tool.name}：${tool.description}` : tool.name"
            @click="pickActiveTool(tool.tool_id)"
          >
            <span class="tool-nav-badge" v-html="toolIcon(tool.tool_id)" />
            <span v-if="!leftCollapsed" class="tool-nav-copy">
              <span class="tool-nav-name">{{ tool.name }}</span>
              <span class="tool-nav-desc">{{ tool.description }}</span>
            </span>
          </button>
        </div>
      </div>
    </aside>

    <main class="toolbox-main">
      <header v-if="activeTool" class="workspace-header">
        <div>
          <div class="workspace-eyebrow">电子取证工作台</div>
          <h1>{{ activeTool.name }}</h1>
          <p>{{ activeTool.description }}</p>
        </div>
      </header>

      <div v-if="globalNotice" class="inline-alert">{{ globalNotice }}</div>

      <section v-if="activeTool" class="tool-stage">
        <div class="workspace-grid">
          <template v-if="activeToolId === 'log_parser'">
            <div class="workspace-column narrow">
              <section class="surface-card">
                <div class="section-title">日志输入</div>
                <p class="section-copy">上传日志后进行基础解析与检索，右侧聊天框负责统一 AI 研判。</p>
                <div class="action-group mt-3">
                  <input class="form-control" type="file" accept=".txt,.log" @change="handleFileSelection($event, setLogSelectedFile)" />
                  <button class="btn btn-outline-primary" :disabled="logUploading" @click="uploadLog">{{ logUploading ? '上传中...' : '上传日志' }}</button>
                  <button class="btn btn-primary" :disabled="logParsing || !logUpload" @click="runLogParse">{{ logParsing ? '解析中...' : '基础解析' }}</button>
                </div>
                <div v-if="logMessage" class="info-block mt-3">{{ logMessage }}</div>
              </section>

              <section class="surface-card">
                <div class="section-title">日志检索</div>
                <p class="section-copy">支持关键字、IP 和正则快速定位。检索结果会同步刷新右侧聊天研判所需上下文。</p>
                <div class="action-group mt-3">
                  <input v-model="logSearchQuery" class="form-control" type="text" placeholder="关键字、IP 或正则" />
                  <button class="btn btn-outline-primary" :disabled="logSearching || !logUpload" @click="runLogSearch()">{{ logSearching ? '搜索中...' : '开始搜索' }}</button>
                  <button class="btn btn-soft" :disabled="!logSearchResult" @click="clearLogSearch">清空结果</button>
                </div>
                <div class="search-options mt-3">
                  <label><input v-model="logSearchRegex" type="checkbox" /> 正则</label>
                  <label><input v-model="logSearchCaseSensitive" type="checkbox" /> 区分大小写</label>
                </div>
              </section>
            </div>

            <div class="workspace-column wide">
              <section class="surface-card">
                <div class="section-title">基础解析概览</div>
                <p class="section-copy">这里保留日志摘要、IP 线索和关键片段。</p>
                <div v-if="!logParsed" class="empty-state">完成基础解析后，这里会展示日志摘要、IP 线索与关键片段。</div>
                <template v-else>
                  <div class="metric-grid">
                    <div v-for="card in logSummaryCards" :key="card.label" class="metric-card">
                      <span>{{ card.label }}</span>
                      <strong>{{ card.value }}</strong>
                    </div>
                  </div>

                  <div class="stack-list mt-4">
                    <div class="soft-panel">
                      <div class="soft-title">解析策略</div>
                      <p class="summary-copy mt-3">{{ logParsed.parse_strategy.overview }}</p>
                      <div class="tool-chip-row mt-3">
                        <span v-for="item in logParsed.parse_strategy.fragment_keywords" :key="item" class="tool-chip">{{ item }}</span>
                      </div>
                    </div>

                    <div class="soft-panel">
                      <div class="soft-title">IP 线索</div>
                      <div v-if="!logParsed.ip_stats.length" class="empty-copy mt-3">未提取到明显的 IP 线索。</div>
                      <div v-else class="tool-chip-row mt-3">
                        <button v-for="ip in logParsed.ip_stats" :key="ip.ip" type="button" class="tool-chip clickable-chip" @click="runLogSearch(ip.ip)">
                          {{ ip.ip }} · {{ ip.count }}
                        </button>
                      </div>
                    </div>

                    <div class="soft-panel">
                      <div class="soft-title">{{ previewTitle }}</div>
                      <pre class="code-box mt-3">{{ previewContent.join('\n') || '暂无预览内容。' }}</pre>
                    </div>

                    <div class="soft-panel">
                      <div class="soft-title">关键片段</div>
                      <div v-if="!logParsed.key_fragments.length" class="empty-copy mt-3">暂无关键片段。</div>
                      <div v-else class="stack-list mt-3">
                        <div v-for="fragment in logParsed.key_fragments" :key="fragment.title" class="soft-panel nested">
                          <div class="info-title" :class="`fragment-title-${fragmentTone(fragment)}`">{{ fragment.title }}</div>
                          <pre class="code-box compact mt-3" :class="`fragment-box-${fragmentTone(fragment)}`">{{ fragment.snippet.join('\n') }}</pre>
                        </div>
                      </div>
                    </div>
                  </div>
                </template>
              </section>
            </div>
          </template>

          <template v-else-if="activeToolId === 'encoding_converter'">
            <div class="workspace-column wide single-span">
              <section class="surface-card">
                <div class="content-head">
                  <div>
                    <div class="section-title">编码转换</div>
                    <p class="section-copy">这里直接嵌入 CyberChef 工作台，用于手工验证、编码转换和配方试验。</p>
                  </div>
                  <div class="button-row">
                    <a class="btn btn-outline-primary" :href="cyberchefBaseUrl" target="_blank" rel="noreferrer">新标签打开 CyberChef</a>
                    <button class="btn btn-soft" @click="reloadCyberChef">重新加载</button>
                  </div>
                </div>

                <div class="cyberchef-wrap mt-3">
                  <div v-if="!cyberchefFrameLoaded && !cyberchefFrameError" class="cyberchef-overlay">CyberChef 正在加载...</div>
                  <div v-if="cyberchefFrameError" class="cyberchef-overlay error">
                    <div>CyberChef 加载失败。</div>
                    <div class="mt-2">请先尝试重新加载，或直接在新标签页打开。</div>
                  </div>
                  <iframe
                    :key="cyberchefUrl"
                    class="cyberchef-frame"
                    :src="cyberchefUrl"
                    title="CyberChef 编码转换工作台"
                    @load="handleCyberChefLoad"
                    @error="handleCyberChefError"
                  />
                </div>
              </section>
            </div>
          </template>

          <template v-else-if="activeToolId === 'hash_tool'">
            <div class="workspace-column narrow">
              <section class="surface-card">
                <div class="section-title">文件输入</div>
                <p class="section-copy">上传目标文件并按需选择算法，生成固定摘要结果。</p>
                <div class="action-group mt-3">
                  <input class="form-control" type="file" @change="handleFileSelection($event, setHashSelectedFile)" />
                  <button class="btn btn-outline-primary" @click="uploadHashToolFile">上传文件</button>
                </div>
                <div class="hash-option-grid mt-3">
                  <label v-for="algorithm in HASH_ALGORITHMS" :key="algorithm" class="hash-option">
                    <input v-model="selectedHashAlgorithms" type="checkbox" :value="algorithm" />
                    <span>{{ algorithm.toUpperCase() }}</span>
                  </label>
                </div>
                <button class="btn btn-primary mt-3 w-100" :disabled="hashRunning || !hashUpload" @click="runHashTool">{{ hashRunning ? '计算中...' : '开始计算' }}</button>
                <div v-if="hashMessage" class="info-block mt-3">{{ hashMessage }}</div>
              </section>
            </div>

            <div class="workspace-column wide">
              <section class="surface-card">
                <div class="section-title">哈希结果</div>
                <p class="section-copy">这里保留各算法摘要值，便于固定证据留存和后续比对。</p>
                <div v-if="!hashToolResult" class="empty-state">上传文件并执行计算后，这里会展示各算法的摘要值。</div>
                <template v-else>
                  <div class="metric-grid compact-grid">
                    <div class="metric-card">
                      <span>文件名</span>
                      <strong>{{ hashDisplayName }}</strong>
                    </div>
                    <div class="metric-card">
                      <span>文件大小</span>
                      <strong>{{ hashToolResult.file_size }} B</strong>
                    </div>
                  </div>
                  <div class="hash-inline-list mt-4">
                    <div v-for="item in hashDisplayItems" :key="item.algorithm" class="hash-inline-item">
                      <span class="hash-inline-label">{{ item.label }}：</span>
                      <code class="hash-inline-value">{{ item.value }}</code>
                    </div>
                  </div>
                </template>
              </section>
            </div>
          </template>

          <template v-else-if="activeToolId === 'sqlite2csv'">
            <div class="workspace-column single-span">
              <section class="surface-card">
                <div class="section-title">数据库输入</div>
                <p class="section-copy">上传 SQLite 文件后可直接浏览表结构、预览数据，并按需导出整库或单表 CSV。</p>
                <div class="sqlite-topbar mt-3">
                  <input class="form-control" type="file" accept=".db,.sqlite,.sqlite3,.db3" @change="handleFileSelection($event, setSqliteSelectedFile)" />
                  <button class="btn btn-outline-primary" @click="uploadSqliteFile">上传数据库</button>
                  <button class="btn btn-soft" :disabled="sqliteBrowserLoading || !sqliteUpload" @click="loadSqliteBrowser">
                    {{ sqliteBrowserLoading ? '加载中...' : '加载结构' }}
                  </button>
                  <button class="btn btn-primary" :disabled="sqliteRunning || !sqliteUpload" @click="runSqliteExport">{{ sqliteRunning ? '导出中...' : '整库导出 ZIP' }}</button>
                </div>
                <div v-if="sqliteMessage" class="info-block mt-3">{{ sqliteMessage }}</div>
                <div v-if="sqliteBrowser" class="metric-grid compact-grid mt-3">
                  <div class="metric-card">
                    <span>数据库</span>
                    <strong>{{ sqliteBrowser.database_name }}</strong>
                  </div>
                  <div class="metric-card">
                    <span>表数量</span>
                    <strong>{{ sqliteBrowser.tables.length }}</strong>
                  </div>
                  <div class="metric-card">
                    <span>当前表</span>
                    <strong>{{ selectedSqliteTable?.table_name || '未选择' }}</strong>
                  </div>
                  <div class="metric-card">
                    <span>当前预览</span>
                    <strong>{{ sqlitePreview ? `${sqlitePreview.returned_rows} / ${sqlitePreview.total_rows}` : '--' }}</strong>
                  </div>
                </div>
              </section>

              <section class="surface-card">
                <div class="section-title">SQLite 可视化浏览器</div>
                <p class="section-copy">数据库输入下方直接展示表列表、字段结构、建表 SQL、数据预览与导出选项，操作路径更直观。</p>
                <div v-if="!sqliteBrowser" class="empty-state">上传数据库并点击“加载结构”后，这里会显示所有表、结构和预览数据。</div>
                <template v-else>
                  <div class="sqlite-browser-grid mt-3">
                    <div class="soft-panel">
                      <div class="soft-title">数据表列表</div>
                      <div class="sqlite-table-list mt-3">
                        <button
                          v-for="table in sqliteBrowser.tables"
                          :key="table.table_name"
                          type="button"
                          class="sqlite-table-item"
                          :class="{ active: selectedSqliteTableName === table.table_name }"
                          @click="selectSqliteTable(table.table_name)"
                        >
                          <span>{{ table.table_name }}</span>
                          <strong>{{ table.row_count }}</strong>
                        </button>
                      </div>
                    </div>

                    <div class="soft-panel">
                      <div class="soft-title">表结构与字段选择</div>
                      <div v-if="!selectedSqliteTable" class="empty-copy mt-3">请选择左侧数据表。</div>
                      <template v-else>
                        <div class="metric-grid compact-grid mt-3">
                          <div class="metric-card">
                            <span>当前表</span>
                            <strong>{{ selectedSqliteTable.table_name }}</strong>
                          </div>
                          <div class="metric-card">
                            <span>字段数量</span>
                            <strong>{{ selectedSqliteTable.columns.length }}</strong>
                          </div>
                        </div>
                        <div class="sqlite-column-list mt-3">
                          <label v-for="column in selectedSqliteTable.columns" :key="column.name" class="sqlite-column-item">
                            <input v-model="sqliteSelectedColumns" type="checkbox" :value="column.name" />
                            <span class="sqlite-column-name">{{ column.name }}</span>
                            <span class="sqlite-column-meta">{{ column.type || 'TEXT' }}</span>
                            <span v-if="column.is_primary_key" class="tool-chip tool-chip-accent">PK</span>
                          </label>
                        </div>
                        <pre v-if="selectedSqliteTable.schema_sql" class="code-box compact mt-3">{{ selectedSqliteTable.schema_sql }}</pre>
                      </template>
                    </div>
                  </div>

                  <div class="sqlite-preview-layout mt-4">
                    <div class="soft-panel">
                      <div class="soft-title">数据预览与导出选项</div>
                      <div v-if="selectedSqliteTable" class="sqlite-preview-toolbar mt-3">
                        <select v-model="sqliteFilter.column" class="form-control">
                          <option v-for="column in selectedSqliteTable.columns" :key="column.name" :value="column.name">{{ column.name }}</option>
                        </select>
                        <select v-model="sqliteFilter.operator" class="form-control">
                          <option v-for="item in SQLITE_FILTER_OPERATORS" :key="item.value" :value="item.value">{{ item.label }}</option>
                        </select>
                        <input
                          v-model="sqliteFilter.value"
                          class="form-control"
                          type="text"
                          placeholder="筛选值，空值运算可留空"
                          :disabled="sqliteFilter.operator === 'is_null' || sqliteFilter.operator === 'not_null'"
                        />
                        <input v-model="sqlitePreviewLimit" class="form-control" type="number" min="1" max="200" placeholder="预览条数" />
                      </div>

                      <div class="sqlite-export-toolbar mt-3">
                        <label class="hash-option">
                          <input v-model="sqliteExportOptions.include_header" type="checkbox" />
                          <span>导出表头</span>
                        </label>
                        <select v-model="sqliteExportOptions.delimiter" class="form-control">
                          <option value=",">逗号 ,</option>
                          <option value=";">分号 ;</option>
                          <option value="|">竖线 |</option>
                          <option value="\\t">制表符 Tab</option>
                        </select>
                        <button class="btn btn-outline-primary" :disabled="sqlitePreviewLoading || !selectedSqliteTable" @click="previewCurrentSqliteTable">
                          {{ sqlitePreviewLoading ? '预览中...' : '刷新预览' }}
                        </button>
                        <button class="btn btn-primary" :disabled="sqliteExporting || !selectedSqliteTable" @click="exportCurrentSqliteTable">
                          {{ sqliteExporting ? '导出中...' : '导出当前表 CSV' }}
                        </button>
                      </div>

                      <div v-if="sqlitePreview" class="metric-grid compact-grid mt-3">
                        <div class="metric-card">
                          <span>预览表</span>
                          <strong>{{ sqlitePreview.table_name }}</strong>
                        </div>
                        <div class="metric-card">
                          <span>返回 / 总行数</span>
                          <strong>{{ sqlitePreview.returned_rows }} / {{ sqlitePreview.total_rows }}</strong>
                        </div>
                        <div class="metric-card">
                          <span>已选字段</span>
                          <strong>{{ sqlitePreview.selected_columns.length }}</strong>
                        </div>
                        <div class="metric-card">
                          <span>筛选字段</span>
                          <strong>{{ sqliteFilter.column || '未设置' }}</strong>
                        </div>
                      </div>

                      <div v-if="sqliteTableExport" class="info-block mt-3">
                        <div>已导出 {{ sqliteTableExport.table_name }}，共 {{ sqliteTableExport.row_count }} 行。</div>
                      </div>

                      <div v-if="sqlitePreview" class="sqlite-preview-table-wrap mt-3">
                        <table class="sqlite-preview-table">
                          <thead>
                            <tr>
                              <th v-for="column in sqlitePreview.selected_columns" :key="column">{{ column }}</th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr v-if="!sqlitePreview.rows.length">
                              <td :colspan="sqlitePreview.selected_columns.length || 1">当前条件下没有数据。</td>
                            </tr>
                            <tr v-for="(row, rowIndex) in sqlitePreview.rows" :key="rowIndex">
                              <td v-for="column in sqlitePreview.selected_columns" :key="`${rowIndex}-${column}`">
                                {{ row[column] ?? '' }}
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </div>

                    <div v-if="sqliteResult" class="soft-panel">
                      <div class="soft-title">整库导出结果</div>
                      <div class="metric-grid compact-grid mt-3">
                        <div class="metric-card">
                          <span>数据库</span>
                          <strong>{{ sqliteResult.database_name }}</strong>
                        </div>
                        <div class="metric-card">
                          <span>数据表数量</span>
                          <strong>{{ sqliteResult.table_count }}</strong>
                        </div>
                      </div>
                      <a class="btn btn-outline-primary mt-3" :href="resolveStorageUrl(sqliteResult.zip_url)" target="_blank" rel="noreferrer">下载 {{ sqliteResult.zip_name }}</a>
                    </div>
                  </div>
                </template>
              </section>
            </div>
          </template>

          <template v-else-if="activeToolId === 'timestamp_parser'">
            <div class="workspace-column wide single-span">
              <section class="surface-card">
                <div class="section-title">时间戳转换</div>
                <p class="section-copy">右侧聊天框负责智能识别，这里保留确定性参数校正和转换结果。</p>
                <div class="two-col-grid mt-3">
                  <div>
                    <label class="mini-title d-block mb-2">时间戳</label>
                    <input v-model="timestampForm.timestamp" class="form-control" type="text" placeholder="输入时间戳" />
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">时间戳类型</label>
                    <select v-model="timestampForm.timestamp_type" class="form-control">
                      <option v-for="item in TIMESTAMP_OPTIONS" :key="item.value" :value="item.value">{{ item.label }}</option>
                    </select>
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">源时区</label>
                    <select v-model="timestampForm.origin_timezone" class="form-control">
                      <option v-for="timezone in TIMEZONE_OPTIONS" :key="timezone" :value="timezone">{{ timezone }}</option>
                    </select>
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">目标时区</label>
                    <select v-model="timestampForm.target_timezone" class="form-control">
                      <option v-for="timezone in TIMEZONE_OPTIONS" :key="timezone" :value="timezone">{{ timezone }}</option>
                    </select>
                  </div>
                </div>
                <button class="btn btn-primary mt-3" :disabled="timestampRunning" @click="runTimestampParser">{{ timestampRunning ? '转换中...' : '开始转换' }}</button>
                <div v-if="timestampMessage" class="info-block mt-3">{{ timestampMessage }}</div>
              </section>

              <section class="surface-card">
                <div class="section-title">转换结果</div>
                <p class="section-copy">AI 识别结果会自动回填这里，之后你仍可手工修正并再次执行转换。</p>
                <div v-if="!timestampResult" class="empty-state">完成转换后，这里会显示标准时间与时区信息。</div>
                <template v-else>
                  <div class="content-grid">
                    <div class="soft-panel">
                      <div class="soft-title">原始输入</div>
                      <pre class="code-box compact mt-3">{{ timestampResult.timestamp }}</pre>
                    </div>
                    <div class="soft-panel">
                      <div class="soft-title">转换时间</div>
                      <pre class="code-box compact mt-3">{{ timestampResult.converted_time }}</pre>
                    </div>
                  </div>
                  <div class="tool-chip-row mt-3">
                    <span class="tool-chip">{{ timestampResult.timestamp_type_label }}</span>
                    <span class="tool-chip">{{ timestampResult.origin_timezone }}</span>
                    <span class="tool-chip">{{ timestampResult.target_timezone }}</span>
                  </div>
                </template>
              </section>
            </div>
          </template>

          <template v-else-if="activeToolId === 'hashcat_gui'">
            <div class="workspace-column wide single-span">
              <section class="surface-card">
                <div class="section-title">Hashcat 控制台</div>
                <p class="section-copy">右侧聊天框负责 Hash 类型识别与参数建议，这里保留文件上传、参数确认和任务控制。</p>
                <div class="two-col-grid mt-3">
                  <div>
                    <label class="mini-title d-block mb-2">Hash 文件</label>
                    <input class="form-control" type="file" accept=".txt,.hash" @change="handleFileSelection($event, setHashcatSelectedFile)" />
                    <button class="btn btn-outline-primary mt-3" @click="uploadHashcatFile">上传 hash 文件</button>
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">Hash 模式</label>
                    <input v-model="hashcatForm.hash_mode" class="form-control" type="number" min="0" />
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">攻击模式</label>
                    <select v-model="hashcatForm.attack_mode" class="form-control">
                      <option :value="0">0 - 字典模式</option>
                      <option :value="3">3 - 掩码模式</option>
                    </select>
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">会话名</label>
                    <input v-model="hashcatForm.session_name" class="form-control" type="text" placeholder="可选" />
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">字典路径</label>
                    <input v-model="hashcatForm.wordlist_path" class="form-control" type="text" placeholder="攻击模式 0 时使用" />
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">掩码</label>
                    <input v-model="hashcatForm.mask" class="form-control" type="text" placeholder="攻击模式 3 时使用" />
                  </div>
                </div>
                <div class="mt-3">
                  <label class="mini-title d-block mb-2">额外参数</label>
                  <input v-model="hashcatForm.extra_args_text" class="form-control" type="text" placeholder="例如 --force --potfile-disable" />
                </div>
                <div class="button-row mt-3">
                  <button class="btn btn-primary" :disabled="hashcatRunning || !hashcatUpload" @click="runHashcatTask">{{ hashcatRunning ? '启动中...' : '启动任务' }}</button>
                  <button class="btn btn-outline-danger" :disabled="!hashcatStatus?.running" @click="stopHashcat">停止任务</button>
                </div>
                <div v-if="hashcatMessage" class="info-block mt-3">{{ hashcatMessage }}</div>
              </section>

              <section class="surface-card">
                <div class="section-title">运行状态</div>
                <p class="section-copy">保留命令和输出尾部，便于确认实际执行情况。</p>
                <div v-if="!hashcatStatus" class="empty-state">状态加载中...</div>
                <template v-else>
                  <div class="metric-grid compact-grid">
                    <div class="metric-card">
                      <span>可用状态</span>
                      <strong>{{ hashcatStatus.configured ? '已配置' : '未配置' }}</strong>
                    </div>
                    <div class="metric-card">
                      <span>任务状态</span>
                      <strong>{{ hashcatStatus.running ? '运行中' : '空闲' }}</strong>
                    </div>
                    <div class="metric-card">
                      <span>PID</span>
                      <strong>{{ hashcatStatus.pid ?? '--' }}</strong>
                    </div>
                    <div class="metric-card">
                      <span>退出码</span>
                      <strong>{{ hashcatStatus.exit_code ?? '--' }}</strong>
                    </div>
                  </div>
                  <div class="stack-list mt-4">
                    <div class="soft-panel">
                      <div class="soft-title">执行命令</div>
                      <pre class="code-box compact mt-3">{{ hashcatStatus.command.join(' ') || '当前无命令' }}</pre>
                    </div>
                    <div class="soft-panel">
                      <div class="soft-title">控制台输出</div>
                      <pre class="code-box mt-3">{{ (hashcatStatus.output_tail ?? []).join('\n') || '当前暂无输出。' }}</pre>
                    </div>
                  </div>
                </template>
              </section>
            </div>
          </template>
        </div>

        <div v-if="activeTool && !activeTool.enabled" class="tool-disabled-overlay">
          <div class="tool-disabled-card">
            <div class="tool-disabled-title">{{ activeTool.disabled_title || '功能暂未开放' }}</div>
            <p class="tool-disabled-message">{{ activeTool.disabled_message || '当前环境未启用该功能。' }}</p>
          </div>
        </div>
      </section>
    </main>

    <aside class="assistant-sidebar" :class="{ collapsed: rightCollapsed }">
      <button type="button" class="rail-toggle rail-toggle-right" :aria-label="rightCollapsed ? '展开 AI 侧栏' : '收起 AI 侧栏'" @click="toggleRightSidebar">
        {{ rightCollapsed ? '‹' : '›' }}
      </button>

      <template v-if="!rightCollapsed">
        <div class="assistant-header">
          <div>
            <div class="workspace-eyebrow">一体化AI智能体</div>
            <h2>{{ activeAiConfig.title }}</h2>
          </div>
          <div class="assistant-meta">
            <span class="meta-pill meta-pill-muted">{{ currentAiModelLabel }}</span>
            <span class="meta-pill" :class="aiStatus?.configured ? 'meta-pill-success' : 'meta-pill-muted'">
              {{ aiStatus?.configured ? 'AI已连接' : '本地回退' }}
            </span>
          </div>
        </div>

        <div class="assistant-toolbar">
          <div class="assistant-mode-toggle">
            <button type="button" class="mode-chip" :class="{ active: aiMode === 'chat' }" @click="aiMode = 'chat'">Chat</button>
            <button type="button" class="mode-chip" :class="{ active: aiMode === 'reasoner' }" @click="aiMode = 'reasoner'">Reasoner</button>
          </div>
          <div class="assistant-toolbar-copy">切换工具会自动切换提示词与聊天线程。</div>
        </div>

        <div ref="assistantScrollRef" class="assistant-chat-scroll">
          <div v-for="message in currentThread" :key="message.id" class="chat-row" :class="message.role">
            <div class="chat-bubble" :class="[message.role, { hint: message.isHint, error: message.status === 'error' }]">
              <div class="chat-meta">
                <span class="chat-author">{{ message.role === 'assistant' ? 'AI 助手' : '你' }}</span>
                <span class="chat-time">{{ formatMessageTime(message.createdAt) }}</span>
                <span v-if="message.mode" class="chat-pill">{{ message.mode }}</span>
                <span v-if="message.source === 'fallback'" class="chat-pill warning">fallback</span>
              </div>

              <div v-if="message.content" class="chat-text">{{ message.content }}</div>
              <div v-else-if="message.status === 'streaming'" class="chat-placeholder typing-indicator" aria-label="正在生成回答">
                <span class="typing-text">正在生成回答</span>
                <span class="typing-dots" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </span>
              </div>

              <div v-if="message.reasoning" class="reasoning-block">
                <button type="button" class="thought-toggle" @click="message.showReasoning = !message.showReasoning">
                  {{ message.showReasoning ? '收起思考流' : '展开思考流' }}
                </button>
                <pre v-if="message.showReasoning" class="code-box compact thought-box mt-2">{{ message.reasoning }}</pre>
              </div>

              <template v-if="getLogResult(message)">
                <div class="chat-result mt-3">
                  <span class="risk-badge" :class="riskBadgeClass(getLogResult(message)!.risk_level)">
                    {{ getLogResult(message)!.risk_level }}
                  </span>
                  <div class="stack-list mt-3">
                    <div v-for="item in getLogResult(message)!.findings" :key="item.title" class="soft-panel nested">
                      <div class="info-title">{{ item.title }}</div>
                      <p v-if="item.explanation" class="summary-copy mt-2">{{ item.explanation }}</p>
                      <ul class="notes-list">
                        <li v-for="evidence in item.evidence" :key="evidence">{{ evidence }}</li>
                      </ul>
                    </div>
                  </div>
                  <div class="mini-section">
                    <div class="mini-title">时间线摘要</div>
                    <ul class="soft-list">
                      <li v-for="item in getLogResult(message)!.timeline_summary" :key="item">{{ item }}</li>
                    </ul>
                  </div>
                  <div class="mini-section">
                    <div class="mini-title">处置建议</div>
                    <ul class="soft-list">
                      <li v-for="item in getLogResult(message)!.recommendations" :key="item">{{ item }}</li>
                    </ul>
                  </div>
                </div>
              </template>

              <template v-if="getHashToolAiResult(message)">
                <div class="chat-result mt-3">
                  <div class="tool-chip-row">
                    <span class="tool-chip tool-chip-accent">{{ getHashToolAiResult(message)!.primary_hash }}</span>
                    <span class="tool-chip">置信度 {{ getHashToolAiResult(message)!.confidence }}</span>
                  </div>
                  <div class="stack-list mt-3">
                    <div v-for="item in getHashToolAiResult(message)!.findings" :key="item" class="soft-panel nested">
                      <p class="summary-copy">{{ item }}</p>
                    </div>
                  </div>
                  <div class="mini-section">
                    <div class="mini-title">建议动作</div>
                    <ul class="soft-list">
                      <li v-for="item in getHashToolAiResult(message)!.recommendations" :key="item">{{ item }}</li>
                    </ul>
                  </div>
                  <ul v-if="getHashToolAiResult(message)!.warnings.length" class="notes-list">
                    <li v-for="warning in getHashToolAiResult(message)!.warnings" :key="warning">{{ warning }}</li>
                  </ul>
                </div>
              </template>

              <template v-if="getSqliteAiResult(message)">
                <div class="chat-result mt-3">
                  <div class="tool-chip-row" v-if="getSqliteAiResult(message)!.current_table_name">
                    <span class="tool-chip tool-chip-accent">{{ getSqliteAiResult(message)!.current_table_name }}</span>
                  </div>
                  <div v-if="getSqliteAiResult(message)!.highlighted_tables.length" class="stack-list mt-3">
                    <div
                      v-for="item in getSqliteAiResult(message)!.highlighted_tables"
                      :key="`${item.table_name}-${item.priority}`"
                      class="soft-panel nested"
                    >
                      <div class="summary-head">
                        <div class="info-title">{{ item.table_name }}</div>
                        <span class="risk-badge" :class="riskBadgeClass(item.priority)">{{ item.priority }}</span>
                      </div>
                      <p class="summary-copy mt-2">{{ item.reason }}</p>
                    </div>
                  </div>
                  <div v-if="getSqliteAiResult(message)!.focus_fields.length" class="mini-section">
                    <div class="mini-title">建议关注字段</div>
                    <div class="tool-chip-row mt-2">
                      <span v-for="field in getSqliteAiResult(message)!.focus_fields" :key="field" class="tool-chip">{{ field }}</span>
                    </div>
                  </div>
                  <div v-if="getSqliteAiResult(message)!.schema_notes.length" class="mini-section">
                    <div class="mini-title">结构观察</div>
                    <ul class="soft-list">
                      <li v-for="item in getSqliteAiResult(message)!.schema_notes" :key="item">{{ item }}</li>
                    </ul>
                  </div>
                  <div class="mini-section">
                    <div class="mini-title">建议动作</div>
                    <ul class="soft-list">
                      <li v-for="item in getSqliteAiResult(message)!.recommendations" :key="item">{{ item }}</li>
                    </ul>
                  </div>
                  <ul v-if="getSqliteAiResult(message)!.warnings.length" class="notes-list">
                    <li v-for="warning in getSqliteAiResult(message)!.warnings" :key="warning">{{ warning }}</li>
                  </ul>
                </div>
              </template>

              <template v-if="getTimestampResult(message)">
                <div class="chat-result mt-3">
                  <div class="tool-chip-row">
                    <span class="tool-chip">{{ getTimestampResult(message)!.timestamp_type }}</span>
                    <span class="tool-chip">{{ getTimestampResult(message)!.origin_timezone }}</span>
                    <span class="tool-chip">{{ getTimestampResult(message)!.target_timezone }}</span>
                  </div>
                  <pre class="code-box compact mt-3">{{ getTimestampResult(message)!.timestamp || '未识别到明确时间戳值。' }}</pre>
                  <ul v-if="getTimestampResult(message)!.warnings.length" class="notes-list">
                    <li v-for="warning in getTimestampResult(message)!.warnings" :key="warning">{{ warning }}</li>
                  </ul>
                </div>
              </template>

              <template v-if="getHashcatAiResult(message)">
                <div class="chat-result mt-3">
                  <div class="tool-chip-row">
                    <span class="tool-chip">mode {{ getHashcatAiResult(message)!.hash_mode }}</span>
                    <span class="tool-chip">attack {{ getHashcatAiResult(message)!.attack_mode }}</span>
                  </div>
                  <div class="stack-list mt-3">
                    <div class="soft-panel">
                      <div class="soft-title">字典路径</div>
                      <div class="summary-copy mt-2">{{ getHashcatAiResult(message)!.wordlist_path || '未提供' }}</div>
                    </div>
                    <div class="soft-panel">
                      <div class="soft-title">掩码</div>
                      <div class="summary-copy mt-2">{{ getHashcatAiResult(message)!.mask || '未提供' }}</div>
                    </div>
                  </div>
                  <ul v-if="getHashcatAiResult(message)!.warnings.length" class="notes-list">
                    <li v-for="warning in getHashcatAiResult(message)!.warnings" :key="warning">{{ warning }}</li>
                  </ul>
                </div>
              </template>

              <template v-if="getEncodingResult(message)">
                <div class="chat-result mt-3">
                  <div class="tool-chip-row">
                    <span class="tool-chip tool-chip-accent">{{ getEncodingResult(message)!.recommended_encoding }}</span>
                    <span v-for="item in getEncodingResult(message)!.suggested_recipe" :key="item" class="tool-chip">{{ item }}</span>
                  </div>
                  <div class="stack-list mt-3">
                    <div v-for="item in getEncodingResult(message)!.candidates" :key="`${item.name}-${item.score}`" class="soft-panel nested">
                      <div class="info-title">{{ item.name }}</div>
                      <div class="info-row mt-2">置信度：{{ item.confidence }} / {{ item.score }}</div>
                      <p class="summary-copy mt-2">{{ item.reason }}</p>
                    </div>
                  </div>
                  <ul v-if="getEncodingResult(message)!.warnings.length" class="notes-list">
                    <li v-for="warning in getEncodingResult(message)!.warnings" :key="warning">{{ warning }}</li>
                  </ul>
                </div>
              </template>
            </div>
          </div>
        </div>

        <div class="assistant-composer">
          <div v-if="assistantNotice" class="inline-alert compact">{{ assistantNotice }}</div>
          <textarea
            v-model="currentAiInput"
            class="form-control assistant-input"
            :disabled="aiBusy"
            rows="4"
            :placeholder="activeAiConfig.placeholder"
            @keydown="handleAiComposerKeydown"
          />
          <div class="composer-footer">
            <div class="composer-tip">Enter 发送，Shift + Enter 换行</div>
            <button class="btn btn-dark" :disabled="aiBusy" @click="runAiForActiveTool">
              {{ aiBusy ? '处理中...' : '发送' }}
            </button>
          </div>
        </div>
      </template>
    </aside>
  </div>
</template>
