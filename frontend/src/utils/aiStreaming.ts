const displayTextSegmenter = (() => {
  const intlWithSegmenter = Intl as typeof Intl & {
    Segmenter?: new (
      locales?: string | string[],
      options?: { granularity?: 'grapheme' | 'word' | 'sentence' },
    ) => {
      segment(input: string): Iterable<{ segment: string }>
    }
  }
  return intlWithSegmenter.Segmenter ? new intlWithSegmenter.Segmenter('zh-CN', { granularity: 'grapheme' }) : null
})()

export function sanitizeDisplayText(value: string | null | undefined): string {
  const text = (value || '')
    .replace(/\r\n/g, '\n')
    .replace(/^\uFEFF/, '')
    .replace(/\u200B/g, '')
    .replace(/(^|\n)\s*\d+\.\s*(?=\n|$)/g, '$1')
  const cleaned = text
    .split('\n')
    .filter((line, index, lines) => {
      const trimmed = line.trim()
      if (!trimmed) {
        const prev = lines[index - 1]?.trim()
        return Boolean(prev)
      }
      return !/^\d+\.\s*$/.test(trimmed)
    })
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
  return cleaned
}

export function normalizeStreamingText(value: string | null | undefined): string {
  return (value || '').replace(/\r\n/g, '\n').replace(/^\uFEFF/, '').replace(/\u200B/g, '')
}

export function humanizeStreamingText(rawContent: string): string {
  const decoded = normalizeStreamingText(rawContent)
    .replace(/\\"/g, '"')
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')

  const loose = decoded
    .replace(/\\u[\dA-Fa-f]{4}/g, ' ')
    .replace(/[{}[\]"]/g, ' ')
    .replace(/\b(?:summary|explanation|reasoning|findings|recommendations|timeline_summary|risk_level)\b\s*:/g, ' ')
    .replace(/[,:]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()

  return sanitizeDisplayText(loose || decoded)
}

export function splitDisplayText(value: string): string[] {
  if (!value) {
    return []
  }
  if (displayTextSegmenter) {
    return Array.from(displayTextSegmenter.segment(value), (part: { segment: string }) => part.segment)
  }
  return Array.from(value)
}

export function getSharedPrefixLength(left: string[], right: string[]): number {
  const maxLength = Math.min(left.length, right.length)
  let index = 0
  while (index < maxLength && left[index] === right[index]) {
    index += 1
  }
  return index
}

export function extractPartialJsonString(content: string, key: string): string {
  const match = content.match(new RegExp(`"${key}"\\s*:\\s*"((?:\\\\.|[^"])*)`))
  if (!match?.[1]) {
    return ''
  }
  return normalizeStreamingText(match[1]).replace(/\\"/g, '"').replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
}

export function extractPartialJsonNumber(content: string, key: string): string {
  const match = content.match(new RegExp(`"${key}"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)`))
  return match?.[1] || ''
}

export function buildToolStreamingDraft(toolId: string, content: string): string {
  if (!content) {
    return ''
  }

  const pushLine = (lines: string[], label: string, value: string) => {
    const normalized = sanitizeDisplayText(value)
    if (normalized) {
      lines.push(`${label}：${normalized}`)
    }
  }

  const lines: string[] = []

  if (toolId === 'encoding_converter') {
    pushLine(lines, '推荐编码', extractPartialJsonString(content, 'recommended_encoding'))
    pushLine(lines, '依据', extractPartialJsonString(content, 'reason'))
    pushLine(lines, '说明', extractPartialJsonString(content, 'explanation'))
    return sanitizeDisplayText(lines.join('\n'))
  }

  if (toolId === 'hashcat_gui') {
    pushLine(lines, 'Hash 模式', extractPartialJsonNumber(content, 'hash_mode'))
    pushLine(lines, '攻击模式', extractPartialJsonNumber(content, 'attack_mode'))
    pushLine(lines, '字典', extractPartialJsonString(content, 'wordlist_path'))
    pushLine(lines, '第二字典', extractPartialJsonString(content, 'secondary_wordlist_path'))
    pushLine(lines, '掩码', extractPartialJsonString(content, 'mask'))
    pushLine(lines, '说明', extractPartialJsonString(content, 'explanation'))
    return sanitizeDisplayText(lines.join('\n'))
  }

  if (toolId === 'timestamp_parser') {
    pushLine(lines, '时间戳', extractPartialJsonString(content, 'timestamp'))
    pushLine(lines, '类型', extractPartialJsonString(content, 'timestamp_type'))
    pushLine(lines, '源时区', extractPartialJsonString(content, 'origin_timezone'))
    pushLine(lines, '目标时区', extractPartialJsonString(content, 'target_timezone'))
    pushLine(lines, '说明', extractPartialJsonString(content, 'explanation'))
    return sanitizeDisplayText(lines.join('\n'))
  }

  if (toolId === 'hash_tool') {
    pushLine(lines, '主哈希', extractPartialJsonString(content, 'primary_hash'))
    pushLine(lines, '摘要', extractPartialJsonString(content, 'summary'))
    pushLine(lines, '发现', extractPartialJsonString(content, 'findings'))
    return sanitizeDisplayText(lines.join('\n'))
  }

  if (toolId === 'sqlite2csv') {
    pushLine(lines, '当前表', extractPartialJsonString(content, 'current_table_name'))
    pushLine(lines, '摘要', extractPartialJsonString(content, 'summary'))
    return sanitizeDisplayText(lines.join('\n'))
  }

  if (toolId === 'log_parser') {
    pushLine(lines, '风险等级', extractPartialJsonString(content, 'risk_level'))
    pushLine(lines, '摘要', extractPartialJsonString(content, 'summary'))
    return sanitizeDisplayText(lines.join('\n'))
  }

  return ''
}

export function selectStreamingDraft(toolId: string, content: string, preview: string): string {
  const previewDraft = sanitizeDisplayText(preview)
  if (previewDraft) {
    return previewDraft
  }

  const structuredDraft = buildToolStreamingDraft(toolId, content)
  if (structuredDraft) {
    return structuredDraft
  }

  return sanitizeDisplayText(humanizeStreamingText(content))
}
