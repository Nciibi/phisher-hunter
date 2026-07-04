import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { isSuspiciousTLD, isHighRiskTLD, getTLD } from '../../shared/utils/url'

export class SuspiciousTLDEngine extends BaseEngine {
  id = 'suspicious-tld'
  name = 'Suspicious TLD Detection'
  description = 'Analyzes top-level domains for suspicious and high-risk TLDs'
  version = '1.0.0'
  weight = 5

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.75

    const tld = context.tld
    details.tld = tld

    if (isHighRiskTLD(tld)) {
      score += 0.7
      reasons.push(
        `High-risk TLD detected: "${tld}". This TLD is commonly used by phishing campaigns.`
      )
    } else if (isSuspiciousTLD(tld)) {
      score += 0.4
      reasons.push(
        `Suspicious TLD detected: "${tld}". Exercise caution with this domain extension.`
      )
    }

    const hostname = context.hostname
    const domainParts = hostname.split('.')
    const registeredName = domainParts[domainParts.length - 2]
    details.registeredName = registeredName

    if (registeredName && registeredName.length > 20) {
      score += 0.1
      reasons.push(`Long domain name (${registeredName.length} chars) with suspicious TLD "${tld}"`)
    }

    if (tld === '.tk' || tld === '.ml' || tld === '.ga' || tld === '.cf' || tld === '.gq') {
      score += 0.1
      reasons.push(`Free TLD "${tld}" - domains are often free and frequently abused`)
    }

    if (registeredName) {
      const digitCount = (registeredName.match(/\d/g) || []).length
      const totalLen = registeredName.length
      if (digitCount / totalLen > 0.3 && isSuspiciousTLD(tld)) {
        score += 0.15
        reasons.push(`Domain name primarily contains digits with suspicious TLD "${tld}"`)
      }
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? `The TLD "${tld}" is frequently used in phishing attacks. Be extremely cautious.`
      : score > 0.2
        ? `The TLD "${tld}" is uncommon. Verify the site's legitimacy.`
        : `TLD "${tld}" appears normal.`

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
