<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'

import { getAiStatus, streamToolAi } from './api/ai'
import { getHashcatHashModes, getHashcatStatus, stopHashcatTask } from './api/hashcat'
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
import {
  getSharedPrefixLength,
  humanizeStreamingText,
  normalizeStreamingText,
  sanitizeDisplayText,
  selectStreamingDraft,
  splitDisplayText,
} from './utils/aiStreaming'
import {
  AI_TOOL_CONFIG,
  DEFAULT_TOOL_ID,
  HASH_ALGORITHMS,
  HASHCAT_ATTACK_MODES,
  SQLITE_FILTER_OPERATORS,
  TIMEZONE_OPTIONS,
  TIMESTAMP_OPTIONS,
  TOOL_ICONS,
  TOOL_ORDER,
} from './constants/tooling'
import type { AiToolConfig, ToolId } from './constants/tooling'
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
  HashcatAttackMode,
  HashcatHashMode,
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
type AssistantMessageStatus = 'ready' | 'streaming' | 'error'

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
  reasoningVisibilityTouched: boolean
  progress: number
  progressLabel: string
  status: AssistantMessageStatus
  isHint?: boolean
}


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
const assistantAutoScroll = ref(true)

const cyberchefFrameLoaded = ref(false)
const cyberchefFrameError = ref(false)
const cyberchefReloadKey = ref(0)
const cyberchefRecipe = ref('')
const cyberchefInput = ref('')

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
const hashcatWordlistSelectedFile = ref<File | null>(null)
const hashcatWordlistUpload = ref<FileUploadResponse | null>(null)
const hashcatSecondaryWordlistSelectedFile = ref<File | null>(null)
const hashcatSecondaryWordlistUpload = ref<FileUploadResponse | null>(null)
const hashcatRunning = ref(false)
const hashcatMessage = ref('')
const hashcatStatus = ref<HashcatTaskStatus | null>(null)
const hashcatHashModes = ref<HashcatHashMode[]>([])
const hashcatModeSearch = ref('')
const hashcatModeDropdownOpen = ref(false)
const hashcatRuntimeInfoOpen = ref(false)
const hashcatForm = reactive({
  hash_mode: 0,
  attack_mode: 0 as HashcatAttackMode,
  wordlist_path: '',
  secondary_wordlist_path: '',
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
let scrollForcePending = false
let assistantLastScrollTop = 0
let ignoreAssistantScrollEvent = false

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
const cyberchefUrl = computed(() => {
  const query = new URLSearchParams({
    embedded: '1',
    reload: String(cyberchefReloadKey.value),
  })
  if (cyberchefRecipe.value.trim()) {
    query.set('recipe', cyberchefRecipe.value.trim())
  }
  if (cyberchefInput.value) {
    query.set('input', encodeCyberChefInput(cyberchefInput.value))
  }
  return `${cyberchefBaseUrl.value}?${query.toString()}`
})
const selectedSqliteTable = computed(() =>
  sqliteBrowser.value?.tables.find((table) => table.table_name === selectedSqliteTableName.value) ?? null,
)
const selectedHashcatAttackMode = computed(
  () => HASHCAT_ATTACK_MODES.find((item) => item.value === Number(hashcatForm.attack_mode)) ?? HASHCAT_ATTACK_MODES[0],
)
const isHashcatPrimaryWordlistMode = computed(() => [0, 1, 6, 7].includes(Number(hashcatForm.attack_mode)))
const isHashcatSecondaryWordlistMode = computed(() => Number(hashcatForm.attack_mode) === 1)
const isHashcatMaskMode = computed(() => [3, 6, 7].includes(Number(hashcatForm.attack_mode)))
const selectedHashcatHashMode = computed(() =>
  hashcatHashModes.value.find((item) => item.mode === Number(hashcatForm.hash_mode)) ?? null,
)
const sortedHashcatHashModes = computed(() => [...hashcatHashModes.value].sort((left, right) => left.mode - right.mode))
const filteredHashcatHashModes = computed(() => {
  const keyword = hashcatModeSearch.value.trim().toLowerCase()
  const source = sortedHashcatHashModes.value
  if (!keyword) {
    return source.slice(0, 200)
  }
  return source
    .filter((item) => item.label.toLowerCase().includes(keyword) || String(item.mode).includes(keyword))
    .slice(0, 200)
})
const hashcatModeTriggerLabel = computed(() => selectedHashcatHashMode.value?.label || `mode ${hashcatForm.hash_mode}`)
const hasHashcatDefaultWordlist = computed(() => Boolean(hashcatStatus.value?.default_wordlist_path))
const hashcatDefaultWordlistDisplay = computed(() => hashcatStatus.value?.default_wordlist_name || 'rockyou.txt')

function getToolOrder(toolId: string): number {
  const index = TOOL_ORDER.indexOf(toolId as ToolId)
  return index === -1 ? TOOL_ORDER.length + 1 : index
}

function createMessageId(): string {
  messageSeed += 1
  return `msg-${messageSeed}`
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

function encodeCyberChefInput(value: string): string {
  if (!value) {
    return ''
  }
  const bytes = new TextEncoder().encode(value)
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize)
    binary += String.fromCharCode(...chunk)
  }
  return btoa(binary)
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
    reasoningVisibilityTouched: false,
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

function isKnowledgeQuestionInput(value: string): boolean {
  const normalized = value.trim().toLowerCase()
  if (!normalized) {
    return false
  }
  const patterns = [
    /什么是/,
    /是什么/,
    /啥是/,
    /是啥/,
    /是什么意思/,
    /含义/,
    /原理/,
    /作用/,
    /用途/,
    /区别/,
    /差异/,
    /怎么理解/,
    /解释一下/,
    /介绍一下/,
    /科普/,
    /为什么/,
    /为何/,
    /优缺点/,
    /如何选择/,
    /怎么用/,
    /如何使用/,
    /what is/,
    /what's/,
    /difference/,
    /meaning/,
    /usage/,
    /use case/,
  ]
  return patterns.some((pattern) => pattern.test(normalized))
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
    setHashcatModeInput(payload.hash_mode)
    hashcatForm.wordlist_path =
      [0, 1, 6, 7].includes(payload.attack_mode) ? payload.wordlist_path ?? hashcatStatus.value?.default_wordlist_name ?? 'rockyou.txt' : ''
    hashcatForm.secondary_wordlist_path = payload.attack_mode === 1 ? payload.secondary_wordlist_path ?? '' : ''
    hashcatForm.mask = [3, 6, 7].includes(payload.attack_mode) ? payload.mask ?? '' : ''
    hashcatForm.session_name = payload.session_name ?? ''
    hashcatForm.extra_args_text = payload.extra_args.join(' ')
    hashcatMessage.value = 'AI 建议已回填到 Hashcat 表单。'
  }

  if (toolId === 'encoding_converter') {
    const payload = result as unknown as EncodingAssistResult
    cyberchefRecipe.value = payload.cyberchef_recipe?.trim() || ''
    cyberchefInput.value = payload.cyberchef_input ?? ''
    assistantNotice.value = 'AI 已回填 CyberChef 参数。'
    reloadCyberChef()
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

  if (toolId === 'hashcat_gui') {
    return {
      upload: hashcatUpload.value
        ? {
            file_id: hashcatUpload.value.file_id,
            original_name: hashcatUpload.value.original_name,
            created_at: hashcatUpload.value.created_at,
          }
        : null,
      current_form: {
        hash_mode: Number(hashcatForm.hash_mode),
        attack_mode: Number(hashcatForm.attack_mode),
        wordlist_path: hashcatForm.wordlist_path || null,
        secondary_wordlist_path: hashcatForm.secondary_wordlist_path || null,
        mask: hashcatForm.mask || null,
        session_name: hashcatForm.session_name || null,
        extra_args: parseExtraArgs(hashcatForm.extra_args_text),
      },
      runtime: hashcatStatus.value
        ? {
            configured: hashcatStatus.value.configured,
            detected_platform: hashcatStatus.value.detected_platform,
            default_wordlist_name: hashcatStatus.value.default_wordlist_name,
            default_wordlist_path: hashcatStatus.value.default_wordlist_path,
            runtime_dir: hashcatStatus.value.runtime_dir,
          }
        : null,
      uploaded_wordlist: hashcatWordlistUpload.value
        ? {
            file_id: hashcatWordlistUpload.value.file_id,
            original_name: hashcatWordlistUpload.value.original_name,
            created_at: hashcatWordlistUpload.value.created_at,
          }
        : null,
      uploaded_secondary_wordlist: hashcatSecondaryWordlistUpload.value
        ? {
            file_id: hashcatSecondaryWordlistUpload.value.file_id,
            original_name: hashcatSecondaryWordlistUpload.value.original_name,
            created_at: hashcatSecondaryWordlistUpload.value.created_at,
          }
        : null,
    }
  }

  return {}
}

function isAssistantScrollNearBottom(node: HTMLElement): boolean {
  return node.scrollHeight - (node.scrollTop + node.clientHeight) <= 48
}

function handleAssistantScroll(): void {
  const node = assistantScrollRef.value
  if (!node) {
    assistantAutoScroll.value = true
    assistantLastScrollTop = 0
    return
  }
  const currentScrollTop = node.scrollTop
  const nearBottom = isAssistantScrollNearBottom(node)

  if (!ignoreAssistantScrollEvent && currentScrollTop < assistantLastScrollTop - 2) {
    assistantAutoScroll.value = false
  } else if (nearBottom) {
    assistantAutoScroll.value = true
  }

  assistantLastScrollTop = currentScrollTop
}

function handleAssistantWheel(event: WheelEvent): void {
  if (event.deltaY < 0) {
    assistantAutoScroll.value = false
  }
}

async function scrollChatToBottom(force = false): Promise<void> {
  await nextTick()
  const node = assistantScrollRef.value
  if (!node) return
  if (!force && !assistantAutoScroll.value) return
  ignoreAssistantScrollEvent = true
  node.scrollTop = node.scrollHeight
  assistantLastScrollTop = node.scrollTop
  if (force) {
    assistantAutoScroll.value = true
  }
  window.requestAnimationFrame(() => {
    ignoreAssistantScrollEvent = false
    handleAssistantScroll()
  })
}

function scheduleScrollChatToBottom(force = false): void {
  scrollForcePending = scrollForcePending || force
  if (scrollFrame !== null) {
    return
  }
  scrollFrame = window.requestAnimationFrame(() => {
    scrollFrame = null
    const nextForce = scrollForcePending
    scrollForcePending = false
    void scrollChatToBottom(nextForce)
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
    reasoningVisibilityTouched: false,
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
    reasoningVisibilityTouched: false,
    progress: mode === 'reasoner' ? 12 : 20,
    progressLabel: mode === 'reasoner' ? '已提交推理请求' : '已提交请求',
    status: 'streaming',
    result: null,
  }
}

function toggleMessageReasoning(message: ChatMessage): void {
  message.reasoningVisibilityTouched = true
  message.showReasoning = !message.showReasoning
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

async function loadHashcatHashModes(): Promise<void> {
  const hashcatTool = tools.value.find((tool) => tool.tool_id === 'hashcat_gui') ?? null
  if (hashcatTool && !hashcatTool.enabled) {
    hashcatHashModes.value = []
    return
  }
  try {
    hashcatHashModes.value = await getHashcatHashModes()
    const currentMode = Number(hashcatForm.hash_mode)
    if (Number.isInteger(currentMode) && currentMode >= 0 && hashcatModeSearch.value.trim()) {
      if (parseHashcatModeValue(hashcatModeSearch.value) === currentMode) {
        setHashcatModeInput(currentMode)
      }
    }
  } catch {
    hashcatHashModes.value = []
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
      binary_source: null,
      detected_platform: 'unknown',
      bundle_dir: null,
      bundled_binary_path: null,
      wordlists_dir: null,
      runtime_dir: null,
      default_wordlist_path: null,
      default_wordlist_name: null,
      running: false,
      task_id: null,
      pid: null,
      command: [],
      started_at: null,
      finished_at: null,
      exit_code: null,
      hash_file: null,
      result_file: null,
      result_lines: [],
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

function setHashcatWordlistSelectedFile(file: File | null): void {
  hashcatWordlistSelectedFile.value = file
}

function setHashcatSecondaryWordlistSelectedFile(file: File | null): void {
  hashcatSecondaryWordlistSelectedFile.value = file
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

async function uploadHashcatWordlistFile(): Promise<void> {
  await uploadSharedToolFile(hashcatWordlistSelectedFile, hashcatWordlistUpload, hashcatMessage, 'hashcat_gui')
  if (hashcatWordlistUpload.value) {
    hashcatMessage.value = `字典上传完成：${hashcatWordlistUpload.value.original_name}，启动时将优先使用该文件。`
  }
}

async function uploadHashcatSecondaryWordlistFile(): Promise<void> {
  await uploadSharedToolFile(
    hashcatSecondaryWordlistSelectedFile,
    hashcatSecondaryWordlistUpload,
    hashcatMessage,
    'hashcat_gui',
  )
  if (hashcatSecondaryWordlistUpload.value) {
    hashcatMessage.value = `第二字典上传完成：${hashcatSecondaryWordlistUpload.value.original_name}。`
  }
}

function clearHashcatWordlistUpload(): void {
  hashcatWordlistUpload.value = null
  hashcatWordlistSelectedFile.value = null
  hashcatMessage.value = '已清除自定义字典，将改用手动路径或默认 rockyou.txt。'
}

function clearHashcatSecondaryWordlistUpload(): void {
  hashcatSecondaryWordlistUpload.value = null
  hashcatSecondaryWordlistSelectedFile.value = null
  hashcatMessage.value = '已清除第二字典上传记录。'
}

function parseHashcatModeValue(value: string): number | null {
  const match = value.trim().match(/^(\d+)/)
  if (!match) {
    return null
  }
  const mode = Number(match[1])
  return Number.isInteger(mode) && mode >= 0 ? mode : null
}

function setHashcatModeInput(mode: number): void {
  const selected = hashcatHashModes.value.find((item) => item.mode === mode) ?? null
  hashcatModeSearch.value = selected?.label || String(mode)
}

function applyHashcatMode(mode: number): void {
  hashcatForm.hash_mode = mode
  setHashcatModeInput(mode)
}

function handleHashcatModeInput(event: Event): void {
  const target = event.target as HTMLInputElement
  hashcatModeSearch.value = target.value
  const parsedMode = parseHashcatModeValue(target.value)
  if (parsedMode !== null) {
    hashcatForm.hash_mode = parsedMode
  }
}

function selectHashcatHashMode(mode: number): void {
  if (Number.isInteger(mode) && mode >= 0) {
    applyHashcatMode(mode)
    hashcatModeDropdownOpen.value = false
  }
}

function handleHashcatModeDropdownToggle(event: Event): void {
  const target = event.target as HTMLDetailsElement
  hashcatModeDropdownOpen.value = Boolean(target?.open)
  if (!hashcatModeDropdownOpen.value) {
    setHashcatModeInput(Number(hashcatForm.hash_mode))
  }
}

function handleHashcatRuntimeToggle(event: Event): void {
  const target = event.target as HTMLDetailsElement
  hashcatRuntimeInfoOpen.value = Boolean(target?.open)
}

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
      wordlist_path: isHashcatPrimaryWordlistMode.value ? hashcatForm.wordlist_path || undefined : undefined,
      wordlist_file_id: isHashcatPrimaryWordlistMode.value ? hashcatWordlistUpload.value?.file_id || undefined : undefined,
      secondary_wordlist_path: isHashcatSecondaryWordlistMode.value ? hashcatForm.secondary_wordlist_path || undefined : undefined,
      secondary_wordlist_file_id: isHashcatSecondaryWordlistMode.value
        ? hashcatSecondaryWordlistUpload.value?.file_id || undefined
        : undefined,
      mask: isHashcatMaskMode.value ? hashcatForm.mask || undefined : undefined,
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
  const requestMode = aiMode.value

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
  const assistantMessage = reactive(createAssistantMessage(toolId, requestMode)) as ChatMessage
  thread.push(userMessage, assistantMessage)
  aiInputs[toolId] = ''
  aiBusy.value = true
  assistantAutoScroll.value = true
  scheduleScrollChatToBottom(true)

  let targetUnits: string[] = []
  let typingTimer: number | null = null
  const clearTypewriterTimer = () => {
    if (typingTimer !== null) {
      window.clearTimeout(typingTimer)
      typingTimer = null
    }
  }

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
      mode: requestMode,
      file_id: fileId,
      context: currentAiContext(toolId),
    }

    let receivedFinal = false
    let pendingReasoning = ''
    let pendingContent = ''
    let pendingContentPreview = ''
    let displayedUnits: string[] = []

    const scheduleTypewriter = () => {
      if (typingTimer !== null) {
        return
      }

      const step = () => {
        const prefixLength = getSharedPrefixLength(displayedUnits, targetUnits)
        if (prefixLength < displayedUnits.length) {
          displayedUnits = displayedUnits.slice(0, prefixLength)
        }

        if (displayedUnits.length < targetUnits.length) {
          displayedUnits = displayedUnits.concat(targetUnits[displayedUnits.length] as string)
        }

        assistantMessage.content = displayedUnits.join('')
        scheduleScrollChatToBottom()

        if (displayedUnits.length < targetUnits.length) {
          typingTimer = window.setTimeout(step, 24)
          return
        }

        typingTimer = null
      }

      typingTimer = window.setTimeout(step, 24)
    }

    const syncAssistantContentQueue = (nextContent: string) => {
      const normalizedContent = sanitizeDisplayText(nextContent)
      if (!normalizedContent) {
        return
      }

      targetUnits = splitDisplayText(normalizedContent)
      scheduleTypewriter()
    }

    const currentDraftContent = () => {
      return selectStreamingDraft(toolId, pendingContent, pendingContentPreview)
    }

    const syncAssistantDraft = () => {
      if (pendingReasoning) {
        assistantMessage.reasoning = normalizeStreamingText(pendingReasoning)
        if (assistantMessage.mode === 'reasoner' && !assistantMessage.reasoningVisibilityTouched) {
          assistantMessage.showReasoning = true
        }
      }

      const draftContent = currentDraftContent()
      if (draftContent) {
        syncAssistantContentQueue(draftContent)
      } else if (pendingContent.trim() && !assistantMessage.content) {
        syncAssistantContentQueue('正在整理结构化结果...')
      }

      scheduleScrollChatToBottom()
    }

    const paintAssistantDraft = () => {
      syncAssistantDraft()
    }

    await streamToolAi(payload, {
      onEvent: (event: ToolAiStreamEvent) => {
        if (event.type === 'reasoning') {
          if (assistantMessage.mode === 'reasoner') {
            pendingReasoning = event.full_text || `${pendingReasoning}${event.delta}`
            assistantMessage.progress = Math.max(assistantMessage.progress, 36)
            assistantMessage.progressLabel = '正在推理'
            paintAssistantDraft()
          }
          return
        }
        if (event.type === 'content') {
          pendingContent = event.full_text || `${pendingContent}${event.delta}`
          pendingContentPreview = event.preview || pendingContentPreview
          assistantMessage.progress = Math.max(assistantMessage.progress, 72)
          assistantMessage.progressLabel = '正在输出'
          paintAssistantDraft()
          return
        }
        if (event.type === 'final') {
          receivedFinal = true
          pendingReasoning = event.reasoning || pendingReasoning
          assistantMessage.status = 'ready'
          assistantMessage.source = event.source
          assistantMessage.mode = event.mode
          assistantMessage.result = event.result
          assistantMessage.reasoning = sanitizeDisplayText(event.reasoning || assistantMessage.reasoning)
          if (assistantMessage.reasoning && assistantMessage.mode === 'reasoner' && !assistantMessage.reasoningVisibilityTouched) {
            assistantMessage.showReasoning = true
          }
          syncAssistantContentQueue(summarizeToolResult(toolId, event.result))
          assistantMessage.progress = 100
          assistantMessage.progressLabel = event.source === 'fallback' ? '已完成（回退）' : '已完成'
          if (!isKnowledgeQuestionInput(userInput)) {
            applyAiResult(toolId, event.result)
          }
        }
      },
    })
    if (!receivedFinal) {
      throw new Error('AI 流式调用未返回最终结果。')
    }
  } catch (error) {
    clearTypewriterTimer()
    targetUnits = []
    assistantNotice.value = ''
    assistantMessage.status = 'error'
    assistantMessage.content = sanitizeDisplayText(getErrorMessage(error, 'AI 调用失败。'))
  } finally {
    aiBusy.value = false
    scheduleScrollChatToBottom()
  }
}

watch(
  () => hashcatForm.attack_mode,
  (attackMode) => {
    if ([0, 1, 6, 7].includes(Number(attackMode))) {
      if (!hashcatForm.wordlist_path && !hashcatWordlistUpload.value && hashcatStatus.value?.default_wordlist_name) {
        hashcatForm.wordlist_path = hashcatStatus.value.default_wordlist_name
      }
    }
  },
  { immediate: true },
)

watch(
  () => hashcatStatus.value?.default_wordlist_name,
  (defaultWordlistName) => {
    if (!defaultWordlistName || !isHashcatPrimaryWordlistMode.value) {
      return
    }
    if (!hashcatForm.wordlist_path && !hashcatWordlistUpload.value) {
      hashcatForm.wordlist_path = defaultWordlistName
    }
  },
  { immediate: true },
)

watch(
  activeToolId,
  (toolId) => {
    ensureThread(toolId)
    assistantNotice.value = ''
    hashcatModeDropdownOpen.value = false
    if (toolId === 'encoding_converter') {
      reloadCyberChef()
    }
    if (toolId === 'hashcat_gui') {
      const hashcatTool = tools.value.find((tool) => tool.tool_id === 'hashcat_gui')
      if (hashcatTool?.enabled) {
        void Promise.all([refreshHashcatStatus(), loadHashcatHashModes()])
      }
    }
    assistantAutoScroll.value = true
    scheduleScrollChatToBottom(true)
  },
  { immediate: true },
)

onMounted(async () => {
  await Promise.all([loadTools(), loadAiMeta()])
  ensureThread(activeToolId.value)
  void loadHashcatHashModes()
  hashcatTimer = window.setInterval(() => {
    if (shouldRefreshHashcatStatus()) {
      void refreshHashcatStatus()
    }
  }, 5000)
  assistantAutoScroll.value = true
  scheduleScrollChatToBottom(true)
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
        <img class="brand-avatar" src="/avatar.png" alt="智能电子取证工具箱" />
        <div class="brand-copy">
          <div class="brand-heading">
            <div class="brand-title">智能电子取证工具箱</div>
            <a
              class="brand-link"
              href="https://github.com/Andyyyyuan/ForensicsToolkits"
              target="_blank"
              rel="noreferrer"
              aria-label="打开项目 GitHub 仓库"
              title="GitHub 仓库"
            >
              <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path
                  d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.27-.01-1.17-.02-2.12-3.2.7-3.88-1.36-3.88-1.36-.52-1.32-1.28-1.67-1.28-1.67-1.04-.72.08-.71.08-.71 1.15.08 1.76 1.18 1.76 1.18 1.02 1.76 2.68 1.25 3.34.95.1-.74.4-1.25.72-1.54-2.56-.29-5.26-1.28-5.26-5.72 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.04 0 0 .97-.31 3.19 1.18a11.1 11.1 0 0 1 5.8 0c2.22-1.49 3.19-1.18 3.19-1.18.62 1.58.23 2.75.11 3.04.74.81 1.18 1.84 1.18 3.1 0 4.45-2.71 5.42-5.29 5.71.41.36.78 1.08.78 2.18 0 1.58-.01 2.85-.01 3.24 0 .31.21.68.8.56A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z"
                />
              </svg>
            </a>
          </div>
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
            :class="{ active: activeToolId === tool.tool_id, disabled: !tool.enabled }"
            :title="tool.name"
            @click="pickActiveTool(tool.tool_id)"
          >
            <span class="tool-nav-badge" v-html="toolIcon(tool.tool_id)" />
            <span class="tool-nav-copy">
              <span class="tool-nav-name">{{ tool.name }}</span>
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
                    <p class="section-copy">一体化嵌入 CyberChef 工作台，用于手工验证、编码转换和配方试验。</p>
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
                <p class="section-copy">上传目标文件并按需选择算法，计算摘要。</p>
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
                <p class="section-copy">输入各类时间戳进行转换，右侧聊天框支持智能识别。</p>
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
                <p class="section-copy">右侧聊天框负责 Hash 类型识别与参数建议，这里保留 Hash 文件、模式选择、字典/组合/掩码参数和任务控制。</p>
                <div class="two-col-grid mt-3">
                  <div>
                    <label class="mini-title d-block mb-2">Hash 文件</label>
                    <input class="form-control" type="file" accept=".txt,.hash" @change="handleFileSelection($event, setHashcatSelectedFile)" />
                    <button class="btn btn-outline-primary mt-3" @click="uploadHashcatFile">上传 hash 文件</button>
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">攻击模式</label>
                    <select v-model="hashcatForm.attack_mode" class="form-control">
                      <option v-for="item in HASHCAT_ATTACK_MODES" :key="item.value" :value="item.value">{{ item.label }}</option>
                    </select>
                    <div class="info-row mt-2">{{ selectedHashcatAttackMode.label }}</div>
                  </div>
                  <div>
                    <label class="mini-title d-block mb-2">会话名</label>
                    <input v-model="hashcatForm.session_name" class="form-control" type="text" placeholder="可选" />
                  </div>
                  <div v-if="isHashcatPrimaryWordlistMode">
                    <label class="mini-title d-block mb-2">主字典路径</label>
                    <input
                      v-model="hashcatForm.wordlist_path"
                      class="form-control"
                      type="text"
                      :disabled="!isHashcatPrimaryWordlistMode"
                      :placeholder="
                        hasHashcatDefaultWordlist
                          ? `未填写时默认使用 ${hashcatDefaultWordlistDisplay}`
                          : '未发现内置 rockyou.txt，请上传字典或手动填写路径'
                      "
                    />
                    <div class="info-row mt-2">
                      {{
                        hashcatWordlistUpload
                          ? `已上传字典：${hashcatWordlistUpload.original_name}，启动时优先使用该文件。`
                          : hasHashcatDefaultWordlist
                            ? `未填写时默认使用 ${hashcatDefaultWordlistDisplay}。`
                            : '当前未发现内置 rockyou.txt，请上传字典或手动填写路径。'
                      }}
                    </div>
                  </div>
                  <div v-if="isHashcatSecondaryWordlistMode">
                    <label class="mini-title d-block mb-2">第二字典路径</label>
                    <input
                      v-model="hashcatForm.secondary_wordlist_path"
                      class="form-control"
                      type="text"
                      :disabled="!isHashcatSecondaryWordlistMode"
                      placeholder="组合模式下必填，可手动填写或上传第二字典"
                    />
                    <div class="info-row mt-2">
                      {{
                        hashcatSecondaryWordlistUpload
                          ? `已上传第二字典：${hashcatSecondaryWordlistUpload.original_name}，启动时优先使用该文件。`
                          : '组合模式必须提供第二字典路径或上传第二字典。'
                      }}
                    </div>
                  </div>
                  <div v-if="isHashcatMaskMode">
                    <label class="mini-title d-block mb-2">掩码</label>
                    <input
                      v-model="hashcatForm.mask"
                      class="form-control"
                      type="text"
                      :disabled="!isHashcatMaskMode"
                      :placeholder="
                        Number(hashcatForm.attack_mode) === 6
                          ? '例如 ?d?d?d?d，表示字典 + 后缀掩码'
                          : Number(hashcatForm.attack_mode) === 7
                            ? '例如 ?d?d?d?d，表示前缀掩码 + 字典'
                            : '例如 ?d?d?d?d?d'
                      "
                    />
                  </div>
                </div>
                <div class="soft-panel mt-3">
                  <div class="soft-title">Hash 模式 / Hash 类型</div>
                  <details class="hashcat-mode-dropdown mt-3" :open="hashcatModeDropdownOpen" @toggle="handleHashcatModeDropdownToggle">
                    <summary class="hashcat-mode-trigger">
                      <span class="hashcat-mode-trigger-label">{{ hashcatModeTriggerLabel }}</span>
                      <span class="hashcat-mode-trigger-arrow">{{ hashcatModeDropdownOpen ? '-' : '+' }}</span>
                    </summary>
                    <div class="hashcat-mode-dropdown-body">
                      <input
                        :value="hashcatModeSearch"
                        class="form-control"
                        type="text"
                        placeholder="输入模式号、算法名或分类后筛选，也可直接输入数字"
                        @input="handleHashcatModeInput"
                        @change="handleHashcatModeInput"
                      />
                      <div class="hashcat-mode-option-list">
                        <button
                          v-for="item in filteredHashcatHashModes"
                          :key="item.mode"
                          type="button"
                          class="hashcat-mode-option"
                          :class="{ active: selectedHashcatHashMode?.mode === item.mode }"
                          @click="selectHashcatHashMode(item.mode)"
                        >
                          {{ item.label }}
                        </button>
                      </div>
                      <div v-if="!filteredHashcatHashModes.length" class="info-row mt-2">未匹配到候选类型，可直接输入数字模式值。</div>
                    </div>
                  </details>
                </div>
                <div v-if="isHashcatPrimaryWordlistMode" class="mt-3">
                  <label class="mini-title d-block mb-2">主字典上传</label>
                  <div class="button-row">
                    <input
                      class="form-control"
                      type="file"
                      accept=".txt,.dict,.lst,.wordlist"
                      :disabled="!isHashcatPrimaryWordlistMode"
                      @change="handleFileSelection($event, setHashcatWordlistSelectedFile)"
                    />
                    <button class="btn btn-outline-primary" :disabled="!isHashcatPrimaryWordlistMode" @click="uploadHashcatWordlistFile">
                      上传字典
                    </button>
                    <button class="btn btn-outline-secondary" :disabled="!hashcatWordlistUpload" @click="clearHashcatWordlistUpload">
                      清除已上传字典
                    </button>
                  </div>
                </div>
                <div v-if="isHashcatSecondaryWordlistMode" class="mt-3">
                  <label class="mini-title d-block mb-2">第二字典上传</label>
                  <div class="button-row">
                    <input
                      class="form-control"
                      type="file"
                      accept=".txt,.dict,.lst,.wordlist"
                      :disabled="!isHashcatSecondaryWordlistMode"
                      @change="handleFileSelection($event, setHashcatSecondaryWordlistSelectedFile)"
                    />
                    <button class="btn btn-outline-primary" :disabled="!isHashcatSecondaryWordlistMode" @click="uploadHashcatSecondaryWordlistFile">
                      上传第二字典
                    </button>
                    <button
                      class="btn btn-outline-secondary"
                      :disabled="!hashcatSecondaryWordlistUpload"
                      @click="clearHashcatSecondaryWordlistUpload"
                    >
                      清除第二字典
                    </button>
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
                <p class="section-copy">保留破解结果、命令和输出尾部，便于确认是否成功命中明文。</p>
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
                      <div class="soft-title">运行结果</div>
                      <pre class="code-box mt-3">{{ (hashcatStatus.result_lines ?? []).join('\n') || '当前暂无破解结果' }}</pre>
                    </div>
                    <div class="soft-panel">
                      <div class="soft-title">执行命令</div>
                      <pre class="code-box compact mt-3">{{ hashcatStatus.command.join(' ') || '当前无命令' }}</pre>
                    </div>
                    <div class="soft-panel">
                      <div class="soft-title">控制台输出</div>
                      <pre class="code-box mt-3">{{ (hashcatStatus.output_tail ?? []).join('\n') || '当前暂无输出。' }}</pre>
                    </div>
                    <details class="soft-panel" :open="hashcatRuntimeInfoOpen" @toggle="handleHashcatRuntimeToggle">
                      <summary class="soft-title">运行时发现</summary>
                      <div class="info-row mt-3">平台：{{ hashcatStatus.detected_platform }}</div>
                      <div class="info-row mt-2">来源：{{ hashcatStatus.binary_source || '未发现' }}</div>
                      <div class="info-row mt-2">当前二进制：{{ hashcatStatus.binary_path || '--' }}</div>
                      <div class="info-row mt-2">Bundle 目录：{{ hashcatStatus.bundle_dir || '--' }}</div>
                      <div class="info-row mt-2">建议二进制路径：{{ hashcatStatus.bundled_binary_path || '--' }}</div>
                      <div class="info-row mt-2">字典目录：{{ hashcatStatus.wordlists_dir || '--' }}</div>
                      <div class="info-row mt-2">默认字典：{{ hashcatStatus.default_wordlist_name || '--' }}</div>
                      <div class="info-row mt-2">运行目录：{{ hashcatStatus.runtime_dir || '--' }}</div>
                    </details>
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
              {{ aiStatus?.configured ? 'AI已连接' : 'ApiKey未配置' }}
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

        <div ref="assistantScrollRef" class="assistant-chat-scroll" @scroll="handleAssistantScroll" @wheel.passive="handleAssistantWheel">
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
                <button type="button" class="thought-toggle" @click="toggleMessageReasoning(message)">
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
                    <div v-if="getHashcatAiResult(message)!.secondary_wordlist_path" class="soft-panel">
                      <div class="soft-title">第二字典路径</div>
                      <div class="summary-copy mt-2">{{ getHashcatAiResult(message)!.secondary_wordlist_path }}</div>
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
