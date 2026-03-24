import { api } from './logParser'
import type { HashcatHashMode, HashcatTaskStatus } from '../types/tools'

export async function getHashcatStatus(): Promise<HashcatTaskStatus> {
  const { data } = await api.get<HashcatTaskStatus>('/hashcat/status')
  return data
}

export async function stopHashcatTask(): Promise<HashcatTaskStatus> {
  const { data } = await api.post<HashcatTaskStatus>('/hashcat/stop')
  return data
}

export async function getHashcatHashModes(): Promise<HashcatHashMode[]> {
  const { data } = await api.get<HashcatHashMode[]>('/hashcat/hash-modes')
  return data
}
