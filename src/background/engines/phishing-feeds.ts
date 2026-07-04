import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { getDomain } from '../../shared/utils/url'
import { KNOWN_PHISHING_FEEDS } from '../../shared/constants'

interface FeedEntry {
  url: string
  domain: string
  source: string
  addedAt: number
}

export class PhishingFeedsEngine extends BaseEngine {
  id = 'phishing-feeds'
  name = 'Known Phishing Feeds'
  description = 'Checks against known phishing domain databases'
  version = '1.0.0'
  weight = 15

  private feedEntries: FeedEntry[] = []
  private feedDomainSet: Set<string> = new Set()
  private lastFetch = 0
  private fetchInProgress = false
  private readonly FETCH_INTERVAL = 1800000
  private readonly FETCH_TIMEOUT = 10000

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.9

    const domain = getDomain(context.url)
    const hostname = context.hostname

    await this.ensureFeedsLoaded()

    if (this.feedDomainSet.has(hostname) || this.feedDomainSet.has(domain)) {
      score = 1.0
      reasons.push(
        `CRITICAL: "${hostname}" is listed in known phishing databases`
      )
      const entries = this.feedEntries.filter(
        e => e.domain === hostname || e.domain === domain
      )
      details.feedMatches = entries.map(e => ({
        source: e.source,
        addedAt: new Date(e.addedAt).toISOString()
      }))
      for (const entry of entries) {
        reasons.push(`Listed on: ${entry.source} (${new Date(entry.addedAt).toLocaleDateString()})`)
      }
    } else {
      const subdomainParts = hostname.split('.')
      for (let i = 1; i < subdomainParts.length - 1; i++) {
        const subDomain = subdomainParts.slice(i).join('.')
        if (this.feedDomainSet.has(subDomain)) {
          score = 0.9
          reasons.push(
            `Subdomain of known phishing domain "${subDomain}" detected`
          )
          confidence = 0.8
          const entries = this.feedEntries.filter(e => e.domain === subDomain)
          details.feedMatchParent = entries.map(e => e.source)
          break
        }
      }
    }

    if (this.feedDomainSet.size === 0) {
      confidence = 0.2
      reasons.push('Phishing feeds not yet loaded - analysis limited')
    } else {
      reasons.push(`Checked against ${this.feedDomainSet.size} known phishing domains`)
      details.feedCount = this.feedDomainSet.size
    }

    score = Math.min(1, score)

    const recommendation = score > 0.8
      ? 'This domain is confirmed as a known phishing site. Do not proceed under any circumstances.'
      : 'Domain not found in known phishing databases.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private async ensureFeedsLoaded(): Promise<void> {
    if (this.feedDomainSet.size > 0 && Date.now() - this.lastFetch < this.FETCH_INTERVAL) {
      return
    }
    if (this.fetchInProgress) return
    this.fetchInProgress = true

    try {
      const results = await Promise.allSettled(
        KNOWN_PHISHING_FEEDS.map(url => this.fetchFeed(url))
      )

      for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
          for (const entry of result.value) {
            const domain = entry.domain.toLowerCase()
            this.feedDomainSet.add(domain)
            this.feedEntries.push(entry)
          }
        }
      }

      this.lastFetch = Date.now()
    } catch {
      // Silent fail - cached data will be used if available
    } finally {
      this.fetchInProgress = false
    }
  }

  private async fetchFeed(url: string): Promise<FeedEntry[]> {
    const entries: FeedEntry[] = []
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), this.FETCH_TIMEOUT)

      const response = await fetch(url, {
        signal: controller.signal,
        headers: { 'User-Agent': 'SeaglesShield/1.0' }
      })
      clearTimeout(timeoutId)

      if (!response.ok) return entries

      const rawText = await response.text()
      const lines = rawText.split('\n').filter(l => l.trim())

      for (const line of lines.slice(0, 10000)) {
        const cleanUrl = line.trim().split(',')[0].trim().split(' ')[0].trim()
        if (!cleanUrl) continue
        try {
          const domain = getDomain(cleanUrl)
          if (domain && !domain.includes(' ')) {
            entries.push({
              url: cleanUrl,
              domain,
              source: url,
              addedAt: Date.now()
            })
          }
        } catch {
          continue
        }
      }
    } catch {
      // Individual feed failure is non-fatal
    }
    return entries
  }

  clearCache(): void {
    this.feedEntries = []
    this.feedDomainSet.clear()
    this.lastFetch = 0
  }

  getFeedCount(): number {
    return this.feedDomainSet.size
  }
}
