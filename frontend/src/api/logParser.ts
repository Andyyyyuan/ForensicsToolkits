import axios from 'axios'
import type { AxiosError } from 'axios'

import type {
  AIAnalysisRequest,
  AIAnalysisResponse,
  FileUploadResponse,
  LogParserStatusResponse,
  LogSearchRequest,
  LogSearchResponse,
  ParsedLogResponse,
} from '../types/logParser'

function resolveDefaultApiBaseUrl(): string {
  if (typeof window === 'undefined') {
    return '/api/v1'
  }

  if (!import.meta.env.DEV) {
    return '/api/v1'
  }

  const protocol = window.location.protocol || 'http:'
  const hostname = window.location.hostname || '127.0.0.1'
  return `${protocol}//${hostname}:8000/api/v1`
}

export const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || resolveDefaultApiBaseUrl()

export const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 60000,
})

export function formatApiError(error: unknown, actionLabel: string): string {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<{ detail?: string }>
    const detail = axiosError.response?.data?.detail
    if (detail) {
      return String(detail)
    }

    if (axiosError.code === 'ECONNABORTED') {
      return `${actionLabel}超时。当前 API 地址：${apiBaseUrl}`
    }

    if (!axiosError.response) {
      const origin = typeof window !== 'undefined' ? window.location.origin : 'unknown'
      return `${actionLabel}失败：无法连接后端。当前前端地址：${origin}；当前 API 地址：${apiBaseUrl}`
    }

    return `${actionLabel}失败：HTTP ${axiosError.response.status}。当前 API 地址：${apiBaseUrl}`
  }

  return `${actionLabel}失败。`
}

export async function uploadLogFile(file: File): Promise<FileUploadResponse> {
  const formData = new FormData()
  formData.append('file', file)

  const { data } = await api.post<FileUploadResponse>('/log-parser/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
  return data
}

export async function getLogParserStatus(): Promise<LogParserStatusResponse> {
  const { data } = await api.get<LogParserStatusResponse>('/log-parser/status')
  return data
}

export async function parseLog(fileId: string): Promise<ParsedLogResponse> {
  const { data } = await api.post<ParsedLogResponse>(`/log-parser/parse/${fileId}`)
  return data
}

export async function searchLog(fileId: string, payload: LogSearchRequest): Promise<LogSearchResponse> {
  const { data } = await api.post<LogSearchResponse>(`/log-parser/search/${fileId}`, payload)
  return data
}

export async function analyzeLog(fileId: string, payload: AIAnalysisRequest): Promise<AIAnalysisResponse> {
  const { data } = await api.post<AIAnalysisResponse>(`/log-parser/analyze/${fileId}`, payload)
  return data
}
