import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { getDomain, hasIpAddress, countDots, countHyphens, countDigits } from '../../shared/utils/url'

export class UrlReputationEngine extends BaseEngine {
  id = 'url-reputation'
  name = 'URL Reputation'
  description = 'Analyzes URL structure for suspicious patterns'
  version = '1.0.0'
  weight = 15

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.8

    const hostname = context.hostname
    const fullUrl = context.url

    if (hasIpAddress(hostname)) {
      score += 0.4
      reasons.push('URL uses IP address instead of domain name')
      details.ipAddress = hostname
    }

    const dotCount = countDots(hostname)
    details.dotCount = dotCount
    if (dotCount >= 4) {
      score += 0.25
      reasons.push(`Excessive subdomains (${hostname.split('.').length - 1} levels)`)
    } else if (dotCount >= 3) {
      score += 0.1
      reasons.push('Multiple subdomain levels detected')
    }

    const hyphenCount = countHyphens(hostname)
    details.hyphenCount = hyphenCount
    if (hyphenCount >= 4) {
      score += 0.3
      reasons.push(`Excessive hyphens in domain name (${hyphenCount} hyphens)`)
    } else if (hyphenCount >= 2) {
      score += 0.1
    }

    const digitCount = countDigits(hostname)
    details.digitCount = digitCount
    const hostnameLen = hostname.replace(/\./g, '').length
    const digitRatio = hostnameLen > 0 ? digitCount / hostnameLen : 0
    if (digitRatio > 0.5) {
      score += 0.35
      reasons.push(`High digit-to-character ratio in domain (${Math.round(digitRatio * 100)}%)`)
    } else if (digitCount >= 5) {
      score += 0.15
      reasons.push(`Multiple digits in domain name (${digitCount} digits)`)
    }

    if (hostname.length > 50) {
      score += 0.2
      reasons.push(`Unusually long domain name (${hostname.length} characters)`)
    }

    if (fullUrl.includes('@')) {
      score += 0.5
      reasons.push('URL contains @ symbol, may be attempting to hide true destination')
    }

    if (fullUrl.includes('//') && fullUrl.indexOf('//') !== fullUrl.indexOf('://') + 2) {
      score += 0.3
      reasons.push('URL contains multiple slash sequences, possible redirection trick')
    }

    if (fullUrl.includes('%')) {
      const encodedCount = (fullUrl.match(/%[0-9a-fA-F]{2}/g) || []).length
      if (encodedCount > 10) {
        score += 0.2
        reasons.push(`Excessive URL encoding detected (${encodedCount} encoded characters)`)
      }
    }

    const parsedUrl = new URL(fullUrl)
    if (parsedUrl.port && !['80', '443'].includes(parsedUrl.port)) {
      score += 0.15
      reasons.push(`Non-standard port used (${parsedUrl.port})`)
    }

    if (!fullUrl.startsWith('https://')) {
      score += 0.1
      reasons.push('Page is not served over HTTPS')
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'This URL exhibits multiple suspicious structural patterns typical of phishing sites'
      : score > 0.2
        ? 'Some minor anomalies detected in URL structure'
        : 'URL structure appears normal'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
