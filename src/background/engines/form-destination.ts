import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { getDomain } from '../../shared/utils/url'
import { BRAND_DOMAINS } from '../../shared/constants'

export class FormDestinationEngine extends BaseEngine {
  id = 'form-destination'
  name = 'Form Destination Analysis'
  description = 'Analyzes where forms submit data and checks for suspicious destinations'
  version = '1.0.0'
  weight = 10

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.85

    const forms = context.forms || []
    details.formCount = forms.length

    if (forms.length === 0) {
      reasons.push('No forms detected on page')
      return this.createResult(score, confidence, reasons, 'No form destinations to analyze.', details)
    }

    const externalForms = forms.filter(f => f.isExternal)
    const sameDomainForms = forms.filter(f => !f.isExternal)

    details.externalFormCount = externalForms.length
    details.sameDomainFormCount = sameDomainForms.length

    if (externalForms.length > 0) {
      score += Math.min(0.5, externalForms.length * 0.15)
      reasons.push(
        `${externalForms.length} form${externalForms.length > 1 ? 's' : ''} submit to external domain(s)`
      )

      const uniqueExternalDomains = [...new Set(externalForms.map(f => f.actionDomain))]
      details.externalDomains = uniqueExternalDomains

      for (const extDomain of uniqueExternalDomains) {
        if (extDomain.includes('.')) {
          const brandCheck = this.checkBrandSpoofing(extDomain, context.hostname)
          if (brandCheck) {
            score += 0.2
            reasons.push(
              `Form submits to "${extDomain}" which appears related to "${brandCheck}" but differs from current domain`
            )
          }
        }
      }

      for (const form of externalForms) {
        if (form.hasPassword) {
          score += 0.2
          reasons.push(
            `Password form submits to external domain: ${form.actionDomain}`
          )
        }
      }
    }

    for (const form of forms) {
      const actionUrl = form.action?.toLowerCase() || ''
      if (actionUrl === 'about:blank' || actionUrl === 'javascript:void(0)' || actionUrl === 'javascript:;') {
        score += 0.1
        reasons.push('Form uses JavaScript-based submission, hiding the true destination')
      }

      const suspiciousPatterns = [
        { pattern: /\.(tk|ml|ga|cf|gq|xyz|top|club|site)/, desc: 'suspicious TLD' },
        { pattern: /\/cgi-bin\//, desc: 'CGI script' },
        { pattern: /\/wp-admin\//, desc: 'WordPress admin' },
        { pattern: /\/wp-content\//, desc: 'WordPress content' },
        { pattern: /\d{5,}\./, desc: 'numeric domain' },
        { pattern: /\.(ru|cn|su|kp|ir)\//, desc: 'high-risk country TLD' },
        { pattern: /amazon.*\.(ru|cn|top|xyz|club)/, desc: 'Amazon spoof' },
        { pattern: /paypal.*\.(ru|cn|top|xyz|club)/, desc: 'PayPal spoof' },
        { pattern: /secure.*\.(ru|cn|top)/, desc: 'fake secure domain' },
        { pattern: /login.*\.(ru|cn|top|xyz|club)/, desc: 'fake login domain' },
      ]

      for (const { pattern, desc } of suspiciousPatterns) {
        if (pattern.test(actionUrl)) {
          score += 0.15
          reasons.push(`Form action URL matches ${desc} pattern: "${actionUrl.slice(0, 60)}..."`)
        }
      }
    }

    const allActionDomains = forms.map(f => f.actionDomain).filter(Boolean)
    const uniqueActionDomains = [...new Set(allActionDomains)]
    if (uniqueActionDomains.length > 3) {
      score += 0.1
      reasons.push(`Forms submit to ${uniqueActionDomains.length} different domains`)
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'Forms on this page submit data to suspicious external destinations. Do not enter any information.'
      : score > 0.2
        ? 'Some form destination anomalies detected. Review where your data would be sent.'
        : 'Form destinations appear appropriate for this site.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private checkBrandSpoofing(externalDomain: string, pageDomain: string): string | null {
    const extMain = externalDomain.split('.')[0]
    if (extMain === pageDomain.split('.')[0]) return null

    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      for (const brandDomain of domains) {
        const brandMain = brandDomain.split('.')[0]
        if (extMain.toLowerCase() === brandMain.toLowerCase()) {
          return brand
        }
      }
    }
    return null
  }
}
