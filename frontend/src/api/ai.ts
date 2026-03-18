import { api, apiBaseUrl } from './logParser'
import type { AiStatusResponse, ToolAiRequest, ToolAiResponse, ToolAiStreamEvent } from '../types/ai'

export async function getAiStatus(): Promise<AiStatusResponse> {
  const { data } = await api.get<AiStatusResponse>('/tools/ai/status')
  return data
}

export async function runToolAi(payload: ToolAiRequest): Promise<ToolAiResponse> {
  const { data } = await api.post<ToolAiResponse>('/tools/ai/assist', payload)
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
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/x-ndjson',
      'Cache-Control': 'no-cache',
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
    }
  }

  const tail = buffer.trim()
  if (tail) {
    handlers.onEvent(JSON.parse(tail) as ToolAiStreamEvent)
  }
}
