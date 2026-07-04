import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { getRegistrableDomain } from '../../shared/utils/url'

interface WhoisCache {
  domain: string
  created: number
  registrar?: string
  cachedAt: number
}

export class DomainAgeEngine extends BaseEngine {
  id = 'domain-age'
  name = 'Domain Age'
  description = 'Checks domain registration age and freshness'
  version = '1.0.0'
  weight = 8

  private cache = new Map<string, WhoisCache>()
  private readonly CACHE_TTL = 3600000
  private readonly NEW_DOMAIN_THRESHOLD_DAYS = 30
  private readonly SUSPICIOUS_THRESHOLD_DAYS = 90

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.5

    const registrableDomain = getRegistrableDomain(context.hostname)
    details.registrableDomain = registrableDomain

    const cached = this.getCached(registrableDomain)
    let domainAge: number | null = null

    if (cached) {
      domainAge = Date.now() - cached.created
      details.registrar = cached.registrar
      details.cached = true
      confidence = 0.6
    } else {
      try {
        const whoisData = await this.fetchWhoisData(registrableDomain)
        if (whoisData) {
          domainAge = Date.now() - whoisData.created
          this.cache.set(registrableDomain, {
            domain: registrableDomain,
            created: whoisData.created,
            registrar: whoisData.registrar,
            cachedAt: Date.now()
          })
          details.registrar = whoisData.registrar
          confidence = 0.7
        }
      } catch {
        reasons.push('Unable to determine domain age')
        confidence = 0.2
      }
    }

    if (domainAge !== null) {
      const ageDays = domainAge / (1000 * 60 * 60 * 24)
      details.ageDays = Math.round(ageDays * 10) / 10

      if (ageDays < 1) {
        score += 0.8
        reasons.push(`Domain registered less than 1 day ago (${Math.round(ageDays * 24)} hours)`)
      } else if (ageDays < 7) {
        score += 0.6
        reasons.push(`Domain registered less than a week ago (${Math.round(ageDays)} days)`)
      } else if (ageDays < this.NEW_DOMAIN_THRESHOLD_DAYS) {
        score += 0.4
        reasons.push(`Recently registered domain (${Math.round(ageDays)} days old)`)
      } else if (ageDays < this.SUSPICIOUS_THRESHOLD_DAYS) {
        score += 0.15
        reasons.push(`Domain is relatively young (${Math.round(ageDays)} days old)`)
      } else {
        const ageYears = Math.round(ageDays / 365 * 10) / 10
        reasons.push(`Domain is well-established (${ageYears} years old)`)
        confidence = 0.8
      }
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'Newly registered domains are frequently used for phishing. Exercise extreme caution.'
      : score > 0.2
        ? 'Domain is relatively young. Verify legitimacy before proceeding.'
        : 'Domain appears to be well-established.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private getCached(domain: string): WhoisCache | undefined {
    const cached = this.cache.get(domain)
    if (cached && Date.now() - cached.cachedAt < this.CACHE_TTL) {
      return cached
    }
    this.cache.delete(domain)
    return undefined
  }

  private async fetchWhoisData(domain: string): Promise<{ created: number; registrar?: string } | null> {
    try {
      const response = await fetch(
        `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`,
        { signal: AbortSignal.timeout(3000) }
      )
      if (!response.ok) return null
      const data = await response.json()
      const events = data.events || []
      const creationEvent = events.find((e: { eventAction: string }) =>
        e.eventAction === 'registration'
      )
      if (creationEvent?.eventDate) {
        return {
          created: new Date(creationEvent.eventDate).getTime(),
          registrar: data.entities?.[0]?.vcardArray?.[1]?.find(
            (v: string[]) => v[0] === 'fn'
          )?.[3]
        }
      }
      return null
    } catch {
      return null
    }
  }

  clearCache(): void {
    this.cache.clear()
  }
}
