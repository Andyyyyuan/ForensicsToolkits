import axios from 'axios'

import type {
  FileUploadResponse,
  LogSearchRequest,
  LogSearchResponse,
  ParsedLogResponse,
} from '../types/logParser'

export const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1'

export const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 60000,
})

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

export async function parseLog(fileId: string): Promise<ParsedLogResponse> {
  const { data } = await api.post<ParsedLogResponse>(`/log-parser/parse/${fileId}`)
  return data
}

export async function searchLog(fileId: string, payload: LogSearchRequest): Promise<LogSearchResponse> {
  const { data } = await api.post<LogSearchResponse>(`/log-parser/search/${fileId}`, payload)
  return data
}
