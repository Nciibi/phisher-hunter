import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

export class CertificateEngine extends BaseEngine {
  id = 'certificate'
  name = 'Certificate Validation'
  description = 'Validates SSL/TLS certificate properties'
  version = '1.0.0'
  weight = 10

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.7

    if (!context.url.startsWith('https://')) {
      score += 0.3
      reasons.push('Page is not served over HTTPS - no TLS certificate')
      confidence = 0.9
      return this.createResult(score, confidence, reasons, 'HTTPS is strongly recommended for all websites.', details)
    }

    const certs = context.certificates
    if (!certs || certs.length === 0) {
      score += 0.1
      reasons.push('Certificate information not available for analysis')
      confidence = 0.3
    } else {
      const leafCert = certs[0]
      details.certificate = {
        issuer: leafCert.issuer,
        subject: leafCert.subject,
        validFrom: new Date(leafCert.validFrom).toISOString(),
        validTo: new Date(leafCert.validTo).toISOString(),
        fingerprint: leafCert.fingerprint
      }

      if (leafCert.isSelfSigned) {
        score += 0.6
        reasons.push('Self-signed certificate detected. Legitimate websites use certificates from trusted Certificate Authorities.')
        confidence = 0.95
      }

      if (Date.now() < leafCert.validFrom) {
        score += 0.3
        reasons.push('Certificate is not yet valid - possible fraudulent certificate')
        confidence = 0.9
      }

      if (Date.now() > leafCert.validTo) {
        score += 0.5
        reasons.push('Certificate has expired. This site may not be properly maintained.')
        confidence = 0.85
      }

      const validityPeriod = leafCert.validTo - leafCert.validFrom
      const validityDays = validityPeriod / (1000 * 60 * 60 * 24)
      details.validityDays = Math.round(validityDays)

      if (validityDays < 30) {
        score += 0.15
        reasons.push(`Unusually short certificate validity (${Math.round(validityDays)} days)`)
      }

      if (validityDays > 825) {
        score += 0.1
        reasons.push(`Certificate validity period (${Math.round(validityDays)} days) exceeds recommended maximum`)
      }

      const certAge = Date.now() - leafCert.validFrom
      const certAgeDays = certAge / (1000 * 60 * 60 * 24)
      if (certAgeDays < 7) {
        score += 0.1
        reasons.push('Certificate was very recently issued')
      }

      if (leafCert.issuer && leafCert.issuer.toLowerCase().includes('localhost')) {
        score += 0.5
        reasons.push('Certificate issued for localhost - not appropriate for production websites')
      }
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'SSL/TLS certificate validation raised concerns. This site may not be properly secured.'
      : score > 0.2
        ? 'Minor certificate issues detected.'
        : 'Certificate appears valid and properly configured.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
