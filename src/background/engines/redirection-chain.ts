import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { getDomain, getRegistrableDomain } from '../../shared/utils/url'

export class RedirectionChainEngine extends BaseEngine {
  id = 'redirection-chain'
  name = 'Redirection Chain Analysis'
  description = 'Analyzes redirect patterns that may lead to phishing pages'
  version = '1.0.0'
  weight = 8

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.7

    const redirectChain = context.redirectChain || []
    details.redirectCount = redirectChain.length

    if (redirectChain.length === 0) {
      reasons.push('No redirect chain detected')
      return this.createResult(score, confidence, reasons, 'No redirects to analyze.', details)
    }

    if (redirectChain.length >= 1) {
      score += Math.min(0.2, redirectChain.length * 0.05)
      reasons.push(`Page was reached through ${redirectChain.length} redirect(s)`)
    }

    if (redirectChain.length >= 3) {
      score += 0.1
      reasons.push('Multiple redirects may be deliberately obfuscating the final destination')
    }

    const uniqueDomains = new Set(redirectChain.map(url => getDomain(url)))
    const uniqueRegistrableDomains = new Set(redirectChain.map(url => {
      try { return getRegistrableDomain(new URL(url).hostname) } catch { return '' }
    }))

    details.uniqueDomains = uniqueDomains.size
    details.uniqueRegistrableDomains = uniqueRegistrableDomains.size

    if (uniqueDomains.size > 3) {
      score += 0.15
      reasons.push(`Redirect chain spans ${uniqueDomains.size} different domains`)
    }

    if (uniqueRegistrableDomains.size > 2) {
      score += 0.1
      reasons.push('Redirect passes through multiple unrelated domain registrations')
    }

    const protocolChanges = redirectChain.filter(url => !url.startsWith('https://')).length
    if (protocolChanges > 0) {
      score += 0.1
      reasons.push('Some redirects use non-HTTPS connections')
    }

    const finalUrl = redirectChain[redirectChain.length - 1]
    const firstUrl = redirectChain[0]
    const firstDomain = getDomain(firstUrl)
    const finalDomain = getDomain(finalUrl)

    if (firstDomain !== finalDomain) {
      score += 0.2
      reasons.push(
        `Redirect chain starts at "${firstDomain}" and ends at "${finalDomain}"`
      )

      const firstRegDomain = this.getRegDomain(firstDomain)
      const finalRegDomain = this.getRegDomain(finalDomain)
      if (firstRegDomain !== finalRegDomain) {
        score += 0.15
        reasons.push(
          `Cross-domain redirect from "${firstRegDomain}" to "${finalRegDomain}"`
        )
      }
    }

    const suspiciousPatterns = [
      /go\./i, /click\./i, /track\./i, /redirect\./i,
      /out\./i, /link\./i, /ad\./i, /adserver\./i
    ]

    const suspiciousRedirectors = redirectChain.filter(url => {
      try {
        const hostname = new URL(url).hostname
        return suspiciousPatterns.some(p => p.test(hostname))
      } catch { return false }
    })

    if (suspiciousRedirectors.length > 0) {
      score += 0.15
      reasons.push('Redirect chain includes known tracking/redirect services')
      details.suspiciousRedirectors = suspiciousRedirectors.map(u => new URL(u).hostname)
    }

    const ipRedirects = redirectChain.filter(url => {
      try {
        const hostname = new URL(url).hostname
        return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
      } catch { return false }
    })
    if (ipRedirects.length > 0) {
      score += 0.2
      reasons.push('Redirect chain contains IP address hops')
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'Complex redirect chain detected. This is a common technique to bypass URL filters and hide the final destination.'
      : score > 0.2
        ? 'Minor redirect chain anomalies detected.'
        : 'Redirect behavior appears normal.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private getRegDomain(hostname: string): string {
    const parts = hostname.split('.')
    return parts.slice(Math.max(0, parts.length - 2)).join('.')
  }
}
