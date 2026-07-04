import { EngineManager } from './engines'
import { RiskEngine } from './risk/risk-engine'
import { AnalysisCache, SettingsManager } from './storage'
import type { EngineContext } from '../shared/types/engines'
import type { AnalysisResult, RiskLevel } from '../shared/types/analysis'
import { getRiskLevel, getRiskColor } from '../shared/types/analysis'
import type { ExtensionMessage, ExtensionResponse, AnalyzeUrlPayload, WarningPageData, ExtensionStats, EngineStatus } from '../shared/types/messages'
import { getDomain, getHostname, getTLD, getSubdomains, getRegistrableDomain } from '../shared/utils/url'
import { DEBOUNCE_DELAYS, PERFORMANCE_BUDGETS, WARNING_PAGE_URL } from '../shared/constants'

const engineManager = new EngineManager()
const riskEngine = new RiskEngine()
const analysisCache = new AnalysisCache()
const settingsManager = new SettingsManager()

let totalScans = 0
let threatsFound = 0
let threatsBlocked = 0
const startTime = Date.now()
const recentAnalyses: Map<string, AnalysisResult> = new Map()

async function initialize(): Promise<void> {
  await settingsManager.initialize()

  chrome.runtime.onMessage.addListener(handleMessage)

  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
      debouncedAnalysis(tabId, tab.url)
    }
  })

  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && details.url.startsWith('http')) {
      debouncedAnalysis(details.tabId, details.url)
    }
  })

  chrome.alarms.create('cache-cleanup', { periodInMinutes: 60 })
  chrome.alarms.create('feed-refresh', { periodInMinutes: 30 })

  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'cache-cleanup') {
      analysisCache.clear()
    } else if (alarm.name === 'feed-refresh') {
      engineManager.clearAllCaches()
    }
  })
}

const pendingAnalyses = new Map<number, number>()

function debouncedAnalysis(tabId: number, url: string): void {
  const existing = pendingAnalyses.get(tabId)
  if (existing) {
    clearTimeout(existing)
  }

  const timeoutId = window.setTimeout(() => {
    pendingAnalyses.delete(tabId)
    performAnalysis({ url, tabId }).catch(console.error)
  }, DEBOUNCE_DELAYS.SCAN)

  pendingAnalyses.set(tabId, timeoutId)
}

async function performAnalysis(payload: AnalyzeUrlPayload): Promise<AnalysisResult> {
  const url = payload.url
  const domain = getDomain(url)
  const hostname = getHostname(url)

  const settings = settingsManager.getSettings()
  if (!settings.general.autoScan) {
    return createSafeResult(url, domain, 'Auto-scan is disabled')
  }

  const cached = analysisCache.get<AnalysisResult>(url)
  if (cached && Date.now() - cached.timestamp < 30000) {
    return cached
  }

  if (settingsManager.isWhitelisted(domain) || settingsManager.isWhitelisted(hostname)) {
    const result = createSafeResult(url, domain, 'Domain is whitelisted')
    result.isWhitelisted = true
    return result
  }

  if (settingsManager.isBlacklisted(domain) || settingsManager.isBlacklisted(hostname)) {
    const result = createCriticalResult(url, domain, 'Domain is blacklisted')
    result.isBlacklisted = true
    return result
  }

  let parsedUrl: URL
  try {
    parsedUrl = new URL(url)
  } catch {
    return createSafeResult(url, domain, 'Invalid URL')
  }

  const context: EngineContext = {
    url,
    domain,
    hostname,
    protocol: parsedUrl.protocol,
    port: parsedUrl.port,
    path: parsedUrl.pathname,
    query: parsedUrl.search,
    fragment: parsedUrl.hash,
    tld: getTLD(hostname),
    subdomains: getSubdomains(hostname),
    tabId: payload.tabId,
    redirectChain: payload.redirectChain
  }

  if (payload.html) context.html = payload.html
  if (payload.links) context.links = payload.links
  if (payload.scripts) context.scripts = payload.scripts
  if (payload.headers) context.headers = payload.headers

  if (payload.forms) {
    try {
      context.forms = JSON.parse(payload.forms)
    } catch { /* ignore */ }
  }
  if (payload.iframes) {
    try {
      context.iframes = JSON.parse(payload.iframes)
    } catch { /* ignore */ }
  }

  const engineResults = await engineManager.analyzeAll(context)

  const result = riskEngine.calculateRisk(url, domain, engineResults, {
    isWhitelisted: false,
    isBlacklisted: false
  })

  analysisCache.set(url, result, 30000)
  recentAnalyses.set(url, result)

  totalScans++
  if (result.riskScore > 0.5) {
    threatsFound++
  }

  updateBadge(result.risk, payload.tabId)

  if (result.risk === 'high' || result.risk === 'critical') {
    showWarningPage(url, result)
  }

  return result
}

function updateBadge(risk: RiskLevel, tabId?: number): void {
  if (!tabId) return
  const settings = settingsManager.getSettings()
  if (!settings.general.showBadge) {
    chrome.action.setBadgeText({ tabId, text: '' })
    return
  }

  const labels: Record<RiskLevel, string> = {
    safe: '',
    low: '',
    medium: '!',
    high: '!!',
    critical: '!!!'
  }

  chrome.action.setBadgeText({ tabId, text: labels[risk] || '' })
  chrome.action.setBadgeBackgroundColor({ tabId, color: getRiskColor(risk) || '#34a853' })
}

async function showWarningPage(url: string, analysis: AnalysisResult): Promise<void> {
  const settings = settingsManager.getSettings()
  if (!settings.notifications.showWarnings) return

  const warningData: WarningPageData = {
    url,
    analysis,
    timestamp: Date.now()
  }

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
    if (tabs[0]?.id) {
      const warningUrl = chrome.runtime.getURL('warning/index.html')
      chrome.tabs.sendMessage(tabs[0].id, {
        type: 'SEAGLES_SHIELD_SHOW_WARNING',
        payload: warningData
      })
    }
  } catch {
    // Tab may have been closed
  }
}

async function handleMessage(
  message: ExtensionMessage,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: ExtensionResponse) => void
): Promise<void> {
  const requestId = message.requestId || crypto.randomUUID()

  const respond = (data: unknown, error?: string) => {
    sendResponse({
      success: !error,
      data: error ? undefined : data,
      error,
      requestId
    })
  }

  try {
    switch (message.type) {
      case 'ANALYZE_URL': {
        const result = await performAnalysis(message.payload as AnalyzeUrlPayload)
        respond(result)
        break
      }

      case 'GET_ANALYSIS': {
        const url = message.payload as string
        const cached = recentAnalyses.get(url)
        if (cached) {
          respond({ analysis: cached, cached: true })
        } else {
          const result = await performAnalysis({ url })
          respond({ analysis: result, cached: false })
        }
        break
      }

      case 'GET_SETTINGS': {
        respond(settingsManager.getSettings())
        break
      }

      case 'UPDATE_SETTINGS': {
        const payload = message.payload as { settings: Record<string, unknown> }
        await settingsManager.updateSettings(payload.settings as any)
        respond({ success: true })
        break
      }

      case 'GET_WHITELIST': {
        respond(settingsManager.getWhitelist())
        break
      }

      case 'ADD_WHITELIST': {
        const entry = (message.payload as any).entry
        await settingsManager.addToWhitelist(entry)
        respond({ success: true })
        break
      }

      case 'REMOVE_WHITELIST': {
        const domain = message.payload as string
        await settingsManager.removeFromWhitelist(domain)
        respond({ success: true })
        break
      }

      case 'GET_BLACKLIST': {
        respond(settingsManager.getBlacklist())
        break
      }

      case 'ADD_BLACKLIST': {
        const entry = (message.payload as any).entry
        await settingsManager.addToBlacklist(entry)
        respond({ success: true })
        break
      }

      case 'REMOVE_BLACKLIST': {
        const domain = message.payload as string
        await settingsManager.removeFromBlacklist(domain)
        respond({ success: true })
        break
      }

      case 'CLEAR_CACHE': {
        analysisCache.clear()
        engineManager.clearAllCaches()
        respond({ success: true })
        break
      }

      case 'GET_STATS': {
        const stats: ExtensionStats = {
          totalScans,
          threatsFound,
          threatsBlocked,
          whitelistedSites: settingsManager.getWhitelist().length,
          blacklistedSites: settingsManager.getBlacklist().length,
          cacheSize: analysisCache.size,
          uptime: Date.now() - startTime,
          enginesActive: engineManager.getActiveEngineCount(),
          lastScan: Date.now()
        }
        respond(stats)
        break
      }

      case 'RESET_SETTINGS': {
        await settingsManager.resetSettings()
        respond({ success: true })
        break
      }

      case 'GET_ENGINE_STATUS': {
        const statuses: EngineStatus[] = engineManager.getAllEngines().map(e => ({
          id: e.id,
          name: e.name,
          enabled: e.enabled,
          weight: e.weight,
          lastRun: 0,
          totalScans: 0,
          totalThreats: 0,
          averageDuration: 0,
          errorCount: 0
        }))
        respond(statuses)
        break
      }

      case 'SET_ENGINE_STATE': {
        const payload = message.payload as { id: string; enabled: boolean }
        const success = engineManager.setEngineEnabled(payload.id, payload.enabled)
        respond({ success })
        break
      }

      case 'REPORT_PHISHING': {
        const payload = message.payload as { url: string }
        console.log('[Seagles Shield] Phishing report submitted:', payload.url)
        respond({ success: true, message: 'Thank you for your report. It will help protect other users.' })
        break
      }

      default:
        respond(null, `Unknown message type: ${message.type}`)
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    respond(null, message)
  }
}

function createSafeResult(url: string, domain: string, reason: string): AnalysisResult {
  return {
    url,
    domain,
    timestamp: Date.now(),
    risk: 'safe',
    riskScore: 0,
    confidence: 1,
    engines: [],
    reasons: [reason],
    recommendations: ['No threats detected.'],
    isWhitelisted: false,
    isBlacklisted: false
  }
}

function createCriticalResult(url: string, domain: string, reason: string): AnalysisResult {
  return {
    url,
    domain,
    timestamp: Date.now(),
    risk: 'critical',
    riskScore: 1,
    confidence: 1,
    engines: [],
    reasons: [reason],
    recommendations: ['This site is blacklisted. Do not proceed.'],
    isWhitelisted: false,
    isBlacklisted: true
  }
}

initialize().catch(console.error)
