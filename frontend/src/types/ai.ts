export type AiMode = 'chat' | 'reasoner'

export interface AiStatusResponse {
  configured: boolean
  chat_model: string | null
  reasoner_model: string | null
}

export interface ToolAiRequest {
  tool_id: string
  user_input: string
  mode: AiMode
  file_id?: string | null
  context?: Record<string, unknown>
}

export interface ToolAiStreamReasoningEvent {
  type: 'reasoning'
  tool_id: string
  delta: string
  full_text?: string
}

export interface ToolAiStreamContentEvent {
  type: 'content'
  tool_id: string
  delta: string
  full_text?: string
  preview?: string
}

export interface ToolAiStreamFinalEvent {
  type: 'final'
  tool_id: string
  mode: AiMode
  model: string | null
  source: 'ai' | 'fallback'
  reasoning: string
  result: Record<string, unknown>
}

export type ToolAiStreamEvent =
  | ToolAiStreamReasoningEvent
  | ToolAiStreamContentEvent
  | ToolAiStreamFinalEvent

export interface EncodingCandidate {
  name: string
  confidence: 'low' | 'medium' | 'high' | string
  score: number
  reason: string
}

export interface EncodingAssistResult {
  recommended_encoding: string
  candidates: EncodingCandidate[]
  suggested_recipe: string[]
  cyberchef_recipe?: string | null
  cyberchef_input?: string | null
  explanation: string
  warnings: string[]
}

export interface HashToolAssistResult {
  summary: string
  primary_hash: string
  findings: string[]
  recommendations: string[]
  warnings: string[]
  confidence: string
}

export interface SqliteHighlightedTable {
  table_name: string
  priority: 'high' | 'medium' | 'low' | string
  reason: string
}

export interface SqliteAssistResult {
  summary: string
  highlighted_tables: SqliteHighlightedTable[]
  current_table_name: string | null
  focus_fields: string[]
  schema_notes: string[]
  recommendations: string[]
  warnings: string[]
}
