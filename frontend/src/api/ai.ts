import { api, apiBaseUrl } from './logParser'
import type { AiStatusResponse, ToolAiRequest, ToolAiStreamEvent } from '../types/ai'

function yieldToBrowser(): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, 0)
  })
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
