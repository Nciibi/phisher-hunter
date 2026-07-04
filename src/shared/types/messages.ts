import type { AnalysisResult } from './analysis'
import type { ExtensionSettings, WhitelistEntry, BlacklistEntry } from './settings'

export type MessageType =
  | 'ANALYZE_URL'
  | 'ANALYSIS_RESULT'
  | 'GET_ANALYSIS'
  | 'GET_SETTINGS'
  | 'UPDATE_SETTINGS'
  | 'GET_WHITELIST'
  | 'ADD_WHITELIST'
  | 'REMOVE_WHITELIST'
  | 'GET_BLACKLIST'
  | 'ADD_BLACKLIST'
  | 'REMOVE_BLACKLIST'
  | 'REPORT_PHISHING'
  | 'CLEAR_CACHE'
  | 'GET_STATS'
  | 'GET_RECENT_SCANS'
  | 'RESET_SETTINGS'
  | 'OPEN_WARNING_PAGE'
  | 'PROCEED_TO_SITE'
  | 'SCAN_PAGE'
  | 'GET_ENGINE_STATUS'
  | 'SET_ENGINE_STATE'
  | 'EXPORT_DATA'
  | 'IMPORT_DATA'

export interface ExtensionMessage<T = unknown> {
  type: MessageType
  payload?: T
  requestId?: string
  timestamp?: number
}

export interface ExtensionResponse<T = unknown> {
  success: boolean
  data?: T
  error?: string
  requestId?: string
}

export interface AnalyzeUrlPayload {
  url: string
  tabId?: number
  html?: string
  forms?: string
  links?: string[]
  scripts?: string[]
  iframes?: string
  headers?: Record<string, string>
  redirectChain?: string[]
}

export interface UpdateSettingsPayload {
  settings: Partial<ExtensionSettings>
}

export interface WhitelistPayload {
  entry: WhitelistEntry
}

export interface BlacklistPayload {
  entry: BlacklistEntry
}

export interface ReportPhishingPayload {
  url: string
  analysis: AnalysisResult
  screenshot?: string
}

export interface WarningPageData {
  url: string
  analysis: AnalysisResult
  timestamp: number
}

export interface ScanResultResponse {
  analysis: AnalysisResult
  cached: boolean
}

export interface ExtensionStats {
  totalScans: number
  threatsFound: number
  threatsBlocked: number
  whitelistedSites: number
  blacklistedSites: number
  cacheSize: number
  uptime: number
  enginesActive: number
  lastScan: number
}

export interface EngineStatus {
  id: string
  name: string
  enabled: boolean
  weight: number
  lastRun: number
  totalScans: number
  totalThreats: number
  averageDuration: number
  errorCount: number
}
