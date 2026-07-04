import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

export class PasswordFieldEngine extends BaseEngine {
  id = 'password-field'
  name = 'Password Field Analysis'
  description = 'Analyzes password field security characteristics'
  version = '1.0.0'
  weight = 5

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.8

    const forms = context.forms || []
    const passwordForms = forms.filter(f => f.hasPassword)

    details.passwordFormCount = passwordForms.length

    if (passwordForms.length === 0) {
      reasons.push('No password fields detected on page')
      return this.createResult(score, confidence, reasons, 'No password field analysis needed.', details)
    }

    if (passwordForms.length > 1) {
      score += 0.1
      reasons.push(`Multiple forms with password fields (${passwordForms.length}) - unusual for legitimate sites`)
    }

    for (const form of passwordForms) {
      const passwordFields = form.fields.filter(f => f.isPassword)

      for (const field of passwordFields) {
        if (field.type === 'text' && field.name.toLowerCase().includes('password')) {
          score += 0.3
          reasons.push('Password field uses "text" type instead of "password" - credentials visible')
        }

        if (field.placeholder && field.placeholder.toLowerCase().includes('password')) {
          details.hasPasswordPlaceholder = true
        }
      }

      if (form.isExternal) {
        score += 0.4
        reasons.push(`Password form submits to external domain: ${form.actionDomain}`)
      }

      if (!form.action || form.action === '' || form.action === '#') {
        score += 0.1
        reasons.push('Password form has no action URL - submission target unclear')
      }

      if (form.action && !form.action.startsWith('https://') && form.action !== '#') {
        score += 0.2
        reasons.push('Password form submits over non-secure connection')
      }

      if (form.fields.filter(f => f.isHidden).length > 3) {
        score += 0.15
        reasons.push('Password form contains multiple hidden fields for data collection')
      }

      const fieldNames = form.fields.map(f => f.name.toLowerCase())
      const extraSensitiveFields = ['ssn', 'social', 'credit', 'card', 'cvv', 'cvc', 'pin', 'atm', 'routing', 'account'].filter(
        p => fieldNames.some(n => n.includes(p))
      )
      if (extraSensitiveFields.length > 0) {
        score += 0.3
        reasons.push(`Password form also requests sensitive data: ${extraSensitiveFields.join(', ')}`)
        details.extraSensitiveFields = extraSensitiveFields
      }

      const passwordFieldCount = form.fields.filter(f => f.isPassword).length
      if (passwordFieldCount >= 2) {
        score += 0.15
        reasons.push(`Form has ${passwordFieldCount} password fields - unusual pattern`)
      }
    }

    const secureContext = context.url.startsWith('https://')
    if (!secureContext && passwordForms.length > 0) {
      score += 0.2
      reasons.push('Password fields present on non-HTTPS page')
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'Password field security concerns detected. Avoid entering credentials.'
      : score > 0.2
        ? 'Some password field anomalies detected.'
        : 'Password fields appear to follow security best practices.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
