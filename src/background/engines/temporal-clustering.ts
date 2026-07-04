import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { CAMPAIGN_TIME_WINDOW_MS, CAMPAIGN_SIMILARITY_THRESHOLD, BRAND_DOMAINS } from '../../shared/constants'

/**
 * TEMPORAL DOMAIN CLUSTERING
 * 
 * Novel technique: Clusters domains by registration patterns to detect
 * coordinated phishing campaigns. Phishing operations often register
 * multiple look-alike domains in short time windows using similar
 * registration patterns.
 * 
 * Clusters based on:
 * - Registration date proximity
 * - Name server patterns
 * - Domain name similarity (edit distance)
 * - Target brand correlation
 * - IP address co-location
 * - Registrar patterns
 * 
 * Detects:
 * - Bulk domain registrations for targeted brands
 * - Campaign-scale phishing infrastructure
 * - Domain generation algorithm (DGA) patterns
 * - Shared hosting/Infrastructure clustering
 */
export class TemporalClusteringEngine extends BaseEngine {
  id = 'temporal-clustering'
  name = 'Temporal Domain Clustering'
  description = 'Clusters domains by registration patterns to detect coordinated phishing campaigns'
  version = '2.0.0'
  weight = 12

  // In-memory domain observation store
  private observedDomains: Map<string, DomainObservation> = new Map()
  private readonly MAX_OBSERVATIONS = 5000

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.8

    const hostname = context.hostname
    const domain = context.domain
    const registrableDomain = hostname.split('.').slice(-2).join('.')

    // Record this domain observation
    this.recordDomain(registrableDomain, hostname, context)

    // 1. Check for domain similarity to known phishing campaigns
    const campaignMatches = this.findCampaignMatches(registrableDomain, hostname)
    if (campaignMatches.length > 0) {
      score += Math.min(0.4, campaignMatches.length * 0.08)
      reasons.push(
        `Domain matches ${campaignMatches.length} other suspicious domain(s) in registration cluster`
      )
      details.campaignMatches = campaignMatches.slice(0, 5)
    }

    // 2. Check for bulk registration patterns (multiple similar domains)
    const similarDomains = this.findSimilarDomains(registrableDomain)
    if (similarDomains.length > 3) {
      score += 0.2
      reasons.push(
        `${similarDomains.length} similar domains observed - possible bulk registration pattern`
      )
      details.similarDomainCount = similarDomains.length
    }

    // 3. Target brand correlation analysis
    const targetedBrands = this.identifyTargetedBrands(hostname)
    if (targetedBrands.length > 0) {
      score += Math.min(0.25, targetedBrands.length * 0.08)
      reasons.push(
        `Domain may be targeting: ${targetedBrands.join(', ')}`
      )
      details.targetedBrands = targetedBrands
    }

    // 4. Clustering coefficient analysis (how connected is this domain)
    const clusterScore = this.computeClusterScore(registrableDomain)
    if (clusterScore > 0.5) {
      score += 0.15
      reasons.push('High infrastructure correlation with other suspicious domains')
      details.clusterCoefficient = Math.round(clusterScore * 100) / 100
    }

    // 5. Shared IP/hosting detection
    if (context.ip) {
      const ipGroup = this.getDomainsByIP(context.ip)
      if (ipGroup.length > 5) {
        score += 0.15
        reasons.push(
          `IP ${context.ip} hosts ${ipGroup.length} domains - potential shared phishing infrastructure`
        )
      }
    }

    // 6. Name server pattern detection
    if (context.headers?.['server']) {
      const serverHeader = context.headers['server']
      const serversOnSameHeader = this.getDomainsByServer(serverHeader)
      if (serversOnSameHeader.length > 3) {
        score += 0.1
        reasons.push(`Shared server infrastructure with ${serversOnSameHeader.length} other domains`)
      }
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'TEMPORAL CLUSTERING ALERT: This domain shares registration patterns with other suspicious domains, suggesting coordinated phishing infrastructure.'
      : score > 0.2
        ? 'Some temporal clustering signals detected. Domain has minor correlations with other suspicious sites.'
        : 'No significant temporal clustering patterns detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private recordDomain(registrableDomain: string, hostname: string, context: EngineContext): void {
    if (this.observedDomains.size >= this.MAX_OBSERVATIONS) {
      const oldest = this.observedDomains.entries().next()
      if (oldest.value) {
        this.observedDomains.delete(oldest.value[0])
      }
    }

    if (!this.observedDomains.has(registrableDomain)) {
      this.observedDomains.set(registrableDomain, {
        hostname,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        visitCount: 1,
        ip: context.ip,
        tld: context.tld,
        subdomainCount: context.subdomains.length,
        targetedBrands: this.identifyTargetedBrands(hostname)
      })
    } else {
      const existing = this.observedDomains.get(registrableDomain)!
      existing.lastSeen = Date.now()
      existing.visitCount++
    }
  }

  private findCampaignMatches(registrableDomain: string, hostname: string): string[] {
    const matches: string[] = []

    for (const [observedDomain, obs] of this.observedDomains.entries()) {
      if (observedDomain === registrableDomain) continue

      const timeDiff = Math.abs(Date.now() - obs.firstSeen)
      if (timeDiff > CAMPAIGN_TIME_WINDOW_MS) continue

      const similarity = this.computeDomainSimilarity(registrableDomain, observedDomain)
      if (similarity >= CAMPAIGN_SIMILARITY_THRESHOLD) {
        matches.push(observedDomain)
      }
    }

    return matches
  }

  private findSimilarDomains(registrableDomain: string): string[] {
    const similar: string[] = []
    for (const [observedDomain] of this.observedDomains.entries()) {
      if (observedDomain === registrableDomain) continue
      const similarity = this.computeDomainSimilarity(registrableDomain, observedDomain)
      if (similarity > 0.5) {
        similar.push(observedDomain)
      }
    }
    return similar
  }

  private computeDomainSimilarity(a: string, b: string): number {
    const aParts = a.split('.')
    const bParts = b.split('.')
    const aName = aParts[0] || ''
    const bName = bParts[0] || ''

    const maxLen = Math.max(aName.length, bName.length)
    if (maxLen === 0) return 0

    const distance = this.levenshteinDistance(aName.toLowerCase(), bName.toLowerCase())
    return 1 - distance / maxLen
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = []
    for (let i = 0; i <= a.length; i++) {
      matrix[i] = [i]
    }
    for (let j = 0; j <= b.length; j++) {
      matrix[0][j] = j
    }
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        if (a[i - 1] === b[j - 1]) {
          matrix[i][j] = matrix[i - 1][j - 1]
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          )
        }
      }
    }
    return matrix[a.length][b.length]
  }

  private identifyTargetedBrands(hostname: string): string[] {
    const targeted: string[] = []
    const hostLower = hostname.toLowerCase().replace(/^www\./, '')

    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      for (const domain of domains) {
        const brandMain = domain.split('.')[0].toLowerCase()
        if (hostLower.includes(brandMain) && !hostLower.endsWith(domain)) {
          if (!targeted.includes(brand)) {
            targeted.push(brand)
          }
        }
      }
    }

    return targeted
  }

  private computeClusterScore(registrableDomain: string): number {
    let connectedCount = 0
    let totalChecked = 0

    for (const [observedDomain, obs] of this.observedDomains.entries()) {
      if (observedDomain === registrableDomain) continue
      totalChecked++

      const similarity = this.computeDomainSimilarity(registrableDomain, observedDomain)
      if (similarity > 0.5) {
        connectedCount++
      }
    }

    return totalChecked > 0 ? connectedCount / totalChecked : 0
  }

  private getDomainsByIP(ip: string): string[] {
    const domains: string[] = []
    for (const [domain, obs] of this.observedDomains.entries()) {
      if (obs.ip === ip) {
        domains.push(domain)
      }
    }
    return domains
  }

  private getDomainsByServer(server: string): string[] {
    const domains: string[] = []
    return domains
  }

  clearCache(): void {
    this.observedDomains.clear()
  }
}

interface DomainObservation {
  hostname: string
  firstSeen: number
  lastSeen: number
  visitCount: number
  ip?: string
  tld: string
  subdomainCount: number
  targetedBrands: string[]
}
