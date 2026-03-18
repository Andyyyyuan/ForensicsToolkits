import { api } from './logParser'
import type { FileUploadResponse } from '../types/logParser'
import type {
  SqliteBrowserResult,
  SqliteExportTableResult,
  SqliteFilterOperator,
  SqlitePreviewResult,
  ToolMeta,
  ToolRunResponse,
} from '../types/tools'

export async function listTools(): Promise<ToolMeta[]> {
  const { data } = await api.get<ToolMeta[]>('/tools')
  return data
}

export async function uploadToolFile(file: File, toolId: string): Promise<FileUploadResponse> {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('tool_id', toolId)

  const { data } = await api.post<FileUploadResponse>('/tools/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
  return data
}

export async function runRegisteredTool(
  toolId: string,
  fileId: string,
  params: Record<string, unknown> = {},
): Promise<ToolRunResponse> {
  const { data } = await api.post<ToolRunResponse>(`/tools/${toolId}/run/${fileId}`, { params })
  return data
}

export async function runRegisteredToolWithoutFile(
  toolId: string,
  params: Record<string, unknown> = {},
): Promise<ToolRunResponse> {
  const { data } = await api.post<ToolRunResponse>(`/tools/${toolId}/run`, { params })
  return data
}

export async function inspectSqliteDatabase(fileId: string): Promise<SqliteBrowserResult> {
  const { data } = await api.get<SqliteBrowserResult>(`/tools/sqlite2csv/browser/${fileId}`)
  return data
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
  const { data } = await api.post<SqlitePreviewResult>(`/tools/sqlite2csv/browser/${fileId}/preview`, payload)
  return data
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
  const { data } = await api.post<SqliteExportTableResult>(`/tools/sqlite2csv/browser/${fileId}/export`, payload)
  return data
}
