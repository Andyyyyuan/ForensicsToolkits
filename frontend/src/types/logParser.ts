export interface FileUploadResponse {
  file_id: string
  original_name: string
  size: number
  created_at: string
}

export interface LogLevelCounts {
  error: number
  warning: number
  info: number
}

export interface LogFragment {
  title: string
  snippet: string[]
}

export interface IpStat {
  ip: string
  count: number
}

export interface ParseStrategy {
  source: 'ai' | 'fallback'
  log_type: string
  overview: string
  error_keywords: string[]
  warning_keywords: string[]
  info_keywords: string[]
  fragment_keywords: string[]
  notes: string[]
}

export interface ParsedLogResponse {
  file_id: string
  original_name: string
  total_lines: number
  level_counts: LogLevelCounts
  has_timestamp: boolean
  preview_lines: string[]
  possible_ips: string[]
  ip_stats: IpStat[]
  key_fragments: LogFragment[]
  parse_strategy: ParseStrategy
}

export interface LogSearchRequest {
  query: string
  use_regex: boolean
  case_sensitive: boolean
  limit: number
}

export interface LogSearchMatch {
  line_number: number
  content: string
}

export interface LogSearchResponse {
  file_id: string
  query: string
  use_regex: boolean
  case_sensitive: boolean
  total_matches: number
  matches: LogSearchMatch[]
}

export interface FindingItem {
  title: string
  evidence: string[]
  explanation?: string
}

export interface AIAnalysisResult {
  summary: string
  risk_level: 'low' | 'medium' | 'high'
  findings: FindingItem[]
  timeline_summary: string[]
  recommendations: string[]
}
