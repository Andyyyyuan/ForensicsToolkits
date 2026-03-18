export interface ToolMeta {
  tool_id: string
  name: string
  description: string
  input_types: string[]
  requires_file: boolean
  enabled: boolean
  disabled_title: string | null
  disabled_message: string | null
}

export interface HashToolResult {
  file_name: string
  file_size: number
  algorithms: string[]
  available_algorithms?: string[]
  hashes: Record<string, string>
}

export interface SqliteCsvExportFile {
  table_name: string
  row_count: number
  columns: string[]
  csv_name: string
  csv_url: string
}

export interface SqliteCsvResult {
  database_name: string
  table_count: number
  tables: SqliteCsvExportFile[]
  zip_name: string
  zip_url: string
}

export interface SqliteColumnInfo {
  name: string
  type: string
  not_null: boolean
  default_value: string | null
  is_primary_key: boolean
}

export interface SqliteTableInfo {
  table_name: string
  row_count: number
  columns: SqliteColumnInfo[]
  schema_sql: string | null
}

export interface SqliteBrowserResult {
  file_id: string
  database_name: string
  tables: SqliteTableInfo[]
}

export type SqliteFilterOperator =
  | 'contains'
  | 'equals'
  | 'starts_with'
  | 'ends_with'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'is_null'
  | 'not_null'

export interface SqlitePreviewFilter {
  column: string
  operator: SqliteFilterOperator
  value?: string | null
}

export interface SqlitePreviewResult {
  table_name: string
  selected_columns: string[]
  available_columns: SqliteColumnInfo[]
  rows: Record<string, unknown>[]
  total_rows: number
  returned_rows: number
}

export interface SqliteExportTableResult {
  table_name: string
  csv_name: string
  csv_url: string
  row_count: number
  columns: string[]
}

export interface TimestampParserParams {
  timestamp: string
  timestamp_type: string
  origin_timezone: string
  target_timezone: string
}

export interface TimestampParserResult {
  timestamp: string
  timestamp_type: string
  timestamp_type_label: string
  origin_timezone: string
  target_timezone: string
  converted_time: string
  supported_timezones: string[]
}

export interface TimestampAIAssistResult {
  timestamp: string
  timestamp_type: string
  origin_timezone: string
  target_timezone: string
  explanation: string
  confidence: string
  warnings: string[]
}

export interface ToolRunResponse {
  tool_id: string
  file_id: string | null
  result: Record<string, unknown>
}

export interface HashcatTaskRequest {
  hash_mode: number
  attack_mode: 0 | 3
  wordlist_path?: string
  mask?: string
  extra_args: string[]
  session_name?: string
}

export interface HashcatTaskStatus {
  enabled: boolean
  disabled_title: string | null
  disabled_message: string | null
  configured: boolean
  binary_path: string | null
  running: boolean
  task_id: string | null
  pid: number | null
  command: string[]
  started_at: string | null
  finished_at: string | null
  exit_code: number | null
  hash_file: string | null
  output_tail: string[]
}

export interface HashcatAIAssistResult {
  hash_mode: number
  attack_mode: 0 | 3
  wordlist_path: string | null
  mask: string | null
  session_name: string | null
  extra_args: string[]
  explanation: string
  confidence: string
  warnings: string[]
}
