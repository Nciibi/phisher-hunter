import type { EngineWeightConfig } from './engines'

export interface ExtensionSettings {
  version: number
  general: GeneralSettings
  engines: EngineSettings
  appearance: AppearanceSettings
  privacy: PrivacySettings
  notifications: NotificationSettings
  advanced: AdvancedSettings
}

export interface GeneralSettings {
  autoScan: boolean
  scanOnNavigation: boolean
  scanOnPageLoad: boolean
  showBadge: boolean
  showNotifications: boolean
  language: string
}

export interface EngineSettings {
  enabled: boolean
  weights: EngineWeightConfig[]
  thresholds: Record<string, number>
}

export interface AppearanceSettings {
  theme: 'light' | 'dark' | 'system'
  compactMode: boolean
  fontSize: 'small' | 'medium' | 'large'
  animationsEnabled: boolean
}

export interface PrivacySettings {
  sendAnonymousStats: boolean
  enableFeeds: boolean
  cacheResults: boolean
  cacheDuration: number
  autoClearCache: boolean
  clearCacheInterval: number
}

export interface NotificationSettings {
  showWarnings: boolean
  showSafePages: boolean
  showRiskChanges: boolean
  soundAlerts: boolean
  desktopNotifications: boolean
}

export interface AdvancedSettings {
  debugMode: boolean
  logLevel: 'error' | 'warn' | 'info' | 'debug'
  maxCacheSize: number
  feedUpdateInterval: number
  apiTimeout: number
  maxRetries: number
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  version: 1,
  general: {
    autoScan: true,
    scanOnNavigation: true,
    scanOnPageLoad: true,
    showBadge: true,
    showNotifications: true,
    language: 'en'
  },
  engines: {
    enabled: true,
    weights: [],
    thresholds: {}
  },
  appearance: {
    theme: 'system',
    compactMode: false,
    fontSize: 'medium',
    animationsEnabled: true
  },
  privacy: {
    sendAnonymousStats: false,
    enableFeeds: true,
    cacheResults: true,
    cacheDuration: 3600,
    autoClearCache: true,
    clearCacheInterval: 86400
  },
  notifications: {
    showWarnings: true,
    showSafePages: false,
    showRiskChanges: true,
    soundAlerts: false,
    desktopNotifications: false
  },
  advanced: {
    debugMode: false,
    logLevel: 'warn',
    maxCacheSize: 10000,
    feedUpdateInterval: 1800,
    apiTimeout: 5000,
    maxRetries: 3
  }
}

export interface WhitelistEntry {
  domain: string
  addedAt: number
  reason?: string
  expiresAt?: number
}

export interface BlacklistEntry {
  domain: string
  addedAt: number
  reason: string
  source?: string
  expiresAt?: number
}
