import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { SUSPICIOUS_KEYWORDS } from '../../shared/constants'

export class CredentialHarvestingEngine extends BaseEngine {
  id = 'credential-harvesting'
  name = 'Credential Harvesting Detection'
  description = 'Detects credential harvesting forms and login page clones'
  version = '1.0.0'
  weight = 12

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.7

    const forms = context.forms || []
    const html = (context.html || '').toLowerCase()
    const title = context.documentProps?.title?.toLowerCase() || ''
    const hostname = context.hostname

    details.formCount = forms.length
    details.hasForms = forms.length > 0

    if (forms.length === 0) {
      if (this.hasLoginIndicators(html, title)) {
        score += 0.2
        reasons.push('Page contains login-related content but no forms detected')
        confidence = 0.4
      } else {
        reasons.push('No forms detected on page')
        return this.createResult(score, confidence, reasons, 'No credential harvesting indicators found.', details)
      }
    }

    const suspiciousKeywordMatches = this.findSuspiciousKeywords(html, title)
    if (suspiciousKeywordMatches.length > 0) {
      details.keywordMatches = suspiciousKeywordMatches
      const keywordScore = Math.min(0.4, suspiciousKeywordMatches.length * 0.08)
      score += keywordScore
      if (suspiciousKeywordMatches.length >= 3) {
        reasons.push(
          `Multiple suspicious keywords detected: ${suspiciousKeywordMatches.slice(0, 5).join(', ')}`
        )
      }
    }

    for (const form of forms) {
      if (form.hasPassword) {
        score += 0.15
        reasons.push('Form contains password field')

        if (form.fields.length > 5) {
          score += 0.1
          reasons.push(`Form has excessive fields (${form.fields.length})`)
        }

        if (form.isExternal) {
          score += 0.3
          reasons.push(
            `Form submits to external domain "${form.actionDomain}" - credentials may be sent to third party`
          )
          details.externalActionDomain = form.actionDomain
        }

        if (form.actionDomain !== hostname) {
          score += 0.2
          reasons.push(
            `Form action domain (${form.actionDomain}) differs from page domain (${hostname})`
          )
        }

        if (form.method.toLowerCase() === 'get') {
          score += 0.05
          reasons.push('Form uses GET method - credentials may be exposed in URL')
        }

        const passwordFieldsCount = form.fields.filter(f => f.isPassword).length
        if (passwordFieldsCount > 1) {
          score += 0.1
          reasons.push(`Multiple password fields detected (${passwordFieldsCount})`)
        }

        const hiddenFields = form.fields.filter(f => f.isHidden)
        if (hiddenFields.length > 2) {
          score += 0.1
          reasons.push(`Excessive hidden form fields (${hiddenFields.length})`)
        }
      }
    }

    const combinedFieldNames = forms.flatMap(f =>
      f.fields.map(field => field.name.toLowerCase())
    )

    const credentialFieldPatterns = [
      'password', 'passwd', 'pwd', 'pass',
      'login', 'signin', 'username', 'user',
      'email', 'mail', 'account', 'ssn',
      'social', 'security', 'pin', 'credit',
      'card', 'cvv', 'cvc', 'bank', 'routing',
      '2fa', 'otp', 'token', 'secret', 'verification'
    ]

    const matchedPatterns = credentialFieldPatterns.filter(p =>
      combinedFieldNames.some(name => name.includes(p))
    )
    if (matchedPatterns.length >= 3) {
      score += 0.15
      reasons.push(
        `Form collects sensitive data: ${matchedPatterns.join(', ')}`
      )
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'This page exhibits strong credential harvesting indicators. Do not enter any personal information.'
      : score > 0.2
        ? 'Minor credential harvesting concerns detected. Verify the site before entering sensitive data.'
        : 'No credential harvesting patterns detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private hasLoginIndicators(html: string, title: string): boolean {
    const loginPatterns = [
      /login/i, /sign.in/i, /signin/i, /log.in/i,
      /account/i, /password/i, /username/i, /credential/i,
      /authenticate/i, /secure.*access/i, /member/i
    ]
    return loginPatterns.some(p => p.test(title) || p.test(html))
  }

  private findSuspiciousKeywords(html: string, title: string): string[] {
    const found: string[] = []
    const text = title + ' ' + html.slice(0, 5000)
    for (const keyword of SUSPICIOUS_KEYWORDS) {
      if (text.includes(keyword.toLowerCase())) {
        found.push(keyword)
      }
    }
    return found
  }
}
