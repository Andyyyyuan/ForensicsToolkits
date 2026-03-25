import { api, apiBaseUrl } from './client'
import type {
  AiStatusResponse,
  ToolAiRequest,
  ToolAiStreamEvent,
} from '../types/ai'
import type {
  FileUploadResponse,
  LogSearchRequest,
  LogSearchResponse,
  ParsedLogResponse,
} from '../types/logParser'
import type {
  HashcatHashMode,
  HashcatTaskStatus,
  SqliteBrowserResult,
  SqliteExportTableResult,
  SqliteFilterOperator,
  SqlitePreviewResult,
  ToolMeta,
  ToolRunResponse,
} from '../types/tools'

interface ToolActionEnvelope<T> {
  tool_id: string
  action: string
  file_id: string | null
  result: T
}

interface ToolExecutionPayload {
  fileId?: string | null
  params?: unknown
}

function yieldToBrowser(): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, 0)
  })
}

export { apiBaseUrl }

export async function listTools(): Promise<ToolMeta[]> {
  const { data } = await api.get<ToolMeta[]>('/tools')
  return data
}

export async function uploadToolFile(toolId: string, file: File): Promise<FileUploadResponse> {
  const formData = new FormData()
  formData.append('file', file)

  const { data } = await api.post<FileUploadResponse>(`/tools/${toolId}/upload`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
  return data
}

export async function runTool(
  toolId: string,
  payload: ToolExecutionPayload = {},
): Promise<ToolRunResponse> {
  const { data } = await api.post<ToolRunResponse>(`/tools/${toolId}/run`, {
    file_id: payload.fileId ?? null,
    params: payload.params ?? {},
  })
  return data
}

export async function getToolAction<T>(toolId: string, action: string): Promise<T> {
  const { data } = await api.get<ToolActionEnvelope<T>>(`/tools/${toolId}/actions/${action}`)
  return data.result
}

export async function runToolAction<T>(
  toolId: string,
  action: string,
  payload: ToolExecutionPayload = {},
): Promise<T> {
  const { data } = await api.post<ToolActionEnvelope<T>>(`/tools/${toolId}/actions/${action}`, {
    file_id: payload.fileId ?? null,
    params: payload.params ?? {},
  })
  return data.result
}

export async function getAiStatus(): Promise<AiStatusResponse> {
  const { data } = await api.get<AiStatusResponse>('/tools/ai/status')
  return data
}

export async function streamToolAi(
  payload: ToolAiRequest,
  handlers: {
    onEvent: (event: ToolAiStreamEvent) => void
  },
): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/tools/ai/assist/stream`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/x-ndjson, text/event-stream',
      'Cache-Control': 'no-cache',
      Pragma: 'no-cache',
    },
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    let detail = ''
    try {
      const data = (await response.json()) as { detail?: string }
      detail = data.detail || ''
    } catch {
      detail = ''
    }
    throw new Error(detail || `AI 流式请求失败：HTTP ${response.status}`)
  }

  if (!response.body) {
    throw new Error('AI 流式响应为空。')
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { value, done } = await reader.read()
    if (done) {
      break
    }

    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() || ''

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) {
        continue
      }
      handlers.onEvent(JSON.parse(trimmed) as ToolAiStreamEvent)
      await yieldToBrowser()
    }
  }

  const tail = buffer.trim()
  if (tail) {
    handlers.onEvent(JSON.parse(tail) as ToolAiStreamEvent)
  }
}

export async function parseLog(fileId: string): Promise<ParsedLogResponse> {
  return runToolAction<ParsedLogResponse>('log_parser', 'parse', { fileId })
}

export async function searchLog(fileId: string, payload: LogSearchRequest): Promise<LogSearchResponse> {
  return runToolAction<LogSearchResponse>('log_parser', 'search', { fileId, params: payload })
}

export async function inspectSqliteDatabase(fileId: string): Promise<SqliteBrowserResult> {
  return runToolAction<SqliteBrowserResult>('sqlite2csv', 'inspect', { fileId })
}

export async function previewSqliteTable(
  fileId: string,
  payload: {
    table_name: string
    selected_columns?: string[]
    filters?: Array<{ column: string; operator: SqliteFilterOperator; value?: string | null }>
    limit?: number
    offset?: number
  },
): Promise<SqlitePreviewResult> {
  return runToolAction<SqlitePreviewResult>('sqlite2csv', 'preview', { fileId, params: payload })
}

export async function exportSqliteTable(
  fileId: string,
  payload: {
    table_name: string
    selected_columns?: string[]
    filters?: Array<{ column: string; operator: SqliteFilterOperator; value?: string | null }>
    include_header?: boolean
    delimiter?: ',' | ';' | '\\t' | '|'
  },
): Promise<SqliteExportTableResult> {
  return runToolAction<SqliteExportTableResult>('sqlite2csv', 'export', { fileId, params: payload })
}

export async function getHashcatStatus(): Promise<HashcatTaskStatus> {
  return getToolAction<HashcatTaskStatus>('hashcat_gui', 'status')
}

export async function stopHashcatTask(): Promise<HashcatTaskStatus> {
  return runToolAction<HashcatTaskStatus>('hashcat_gui', 'stop')
}

export async function getHashcatHashModes(): Promise<HashcatHashMode[]> {
  return getToolAction<HashcatHashMode[]>('hashcat_gui', 'hash-modes')
}
