import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { BRAND_DOMAINS, SUSPICIOUS_KEYWORDS } from '../../shared/constants'
import { getBrandForDomain } from '../../shared/utils/url'
import { extractBrandKeywords } from '../../shared/utils/domain'

export class BrandImpersonationEngine extends BaseEngine {
  id = 'brand-impersonation'
  name = 'Brand Impersonation Detection'
  description = 'Detects pages impersonating known brands and organizations'
  version = '1.0.0'
  weight = 12

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.7

    const hostname = context.hostname
    const html = (context.html || '').toLowerCase()
    const title = (context.documentProps?.title || '').toLowerCase()
    const knownBrand = getBrandForDomain(hostname)

    let isBrandPage = false
    let brandMatch: string | null = null

    if (knownBrand) {
      isBrandPage = true
      brandMatch = knownBrand
      details.actualBrand = knownBrand
    }

    const brandKeywords = extractBrandKeywords(html + ' ' + title)
    details.brandKeywordsFound = brandKeywords

    if (brandKeywords.length > 0) {
      if (!isBrandPage) {
        score += Math.min(0.5, brandKeywords.length * 0.12)
        confidence = Math.min(0.9, 0.7 + brandKeywords.length * 0.05)
        brandMatch = brandKeywords[0]
        reasons.push(
          `Page appears to impersonate "${brandKeywords[0]}" but domain does not match`
        )
        if (brandKeywords.length > 1) {
          reasons.push(
            `Multiple brand references found: ${brandKeywords.join(', ')}`
          )
        }
      } else {
        const brandDomain = BRAND_DOMAINS[knownBrand]?.[0]
        if (brandDomain && hostname !== brandDomain) {
          const subdomainMatch = hostname.endsWith('.' + brandDomain)
          if (!subdomainMatch) {
            score += 0.1
            reasons.push(
              `Subdomain "${hostname}" differs from official "${brandDomain}"`
            )
          }
        }
      }
    }

    const hasLoginForm = (context.html || '').toLowerCase().includes('password') ||
      (context.forms?.some(f => f.hasPassword) ?? false)

    if (hasLoginForm && brandKeywords.length > 0 && !isBrandPage) {
      score += 0.2
      reasons.push(
        `Login form detected on page impersonating ${brandKeywords[0]}`
      )
    }

    const brandNameVariations = brandKeywords.map(b => b.toLowerCase().replace(/[^a-z0-9]/g, ''))
    const hostnameWithoutTld = hostname.split('.').slice(0, -1).join('.')
    for (const variation of brandNameVariations) {
      if (hostnameWithoutTld.includes(variation) && !isBrandPage) {
        score += 0.15
        reasons.push(
          `Brand name "${variation}" embedded in non-brand domain`
        )
      }
    }

    const hasSecurityAlerts = SUSPICIOUS_KEYWORDS.some(kw =>
      html.includes(kw.toLowerCase())
    )
    if (hasSecurityAlerts && brandKeywords.length > 0) {
      score += 0.1
      reasons.push(
        'Page uses urgent security language to impersonate a trusted brand'
      )
    }

    const hasBrandInTitle = brandKeywords.some(b =>
      title.includes(b.toLowerCase())
    )
    if (hasBrandInTitle && !isBrandPage) {
      score += 0.1
      reasons.push('Page title references a brand not matching the domain')
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? `This page appears to impersonate "${brandMatch || 'a known brand'}". Do not enter credentials.`
      : score > 0.2
        ? 'Minor brand impersonation signals detected.'
        : 'No brand impersonation detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
