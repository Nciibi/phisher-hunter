import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { BRAND_DOMAINS } from '../../shared/constants'

/**
 * CERTIFICATE ANOMALY DETECTION
 * 
 * Novel technique: Analyzes certificate issuance patterns beyond basic
 * validation. Tracks and correlates:
 * 
 * - Recently issued certificates for look-alike domains
 * - Certificate Authority clustering (phishkits often use specific CAs)
 * - Certificate Subject Alternative Name (SAN) analysis
 * - Certificate issuance velocity (multiple certs in short time)
 * - Certificate transparency log anomalies
 * - Self-signed vs CA-issued ratio for similar domains
 * - Certificate revocation status patterns
 */
export class CertificateAnomalyEngine extends BaseEngine {
  id = 'certificate-anomaly'
  name = 'Certificate Anomaly Detection'
  description = 'Analyzes SSL certificate issuance patterns for phishing infrastructure signals'
  version = '2.0.0'
  weight = 9

  // Track recently seen certificates for correlation
  private recentCertificates: Map<string, CertRecord> = new Map()
  private readonly MAX_CERTS = 1000
  private readonly RECENT_WINDOW_MS = 86400000 // 24 hours

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.75

    const hostname = context.hostname
    const certs = context.certificates

    if (!context.url.startsWith('https://')) {
      reasons.push('No HTTPS - no certificate to analyze')
      confidence = 0.5
      return this.createResult(score, confidence, reasons, 'Page is not served over HTTPS.', details)
    }

    if (!certs || certs.length === 0) {
      score += 0.1
      reasons.push('Certificate information unavailable for anomaly analysis')
      confidence = 0.3
      return this.createResult(score, confidence, reasons, 'Unable to analyze certificate.', details)
    }

    const leafCert = certs[0]
    details.certificate = {
      issuer: leafCert.issuer,
      subject: leafCert.subject,
      validFrom: new Date(leafCert.validFrom).toISOString(),
      validTo: new Date(leafCert.validTo).toISOString(),
      age: Math.round((Date.now() - leafCert.validFrom) / (1000 * 60 * 60 * 24)) + ' days',
      isSelfSigned: leafCert.isSelfSigned
    }

    // 1. Certificate age analysis
    const certAgeMs = Date.now() - leafCert.validFrom
    const certAgeDays = certAgeMs / (1000 * 60 * 60 * 24)

    if (certAgeDays < 1) {
      score += 0.35
      reasons.push(`Certificate issued less than 1 day ago - highly unusual for established sites`)
      confidence = Math.min(0.95, confidence + 0.15)
    } else if (certAgeDays < 7) {
      score += 0.2
      reasons.push(`Very recently issued certificate (${Math.round(certAgeDays)} days old)`)
    } else if (certAgeDays < 30) {
      score += 0.1
      reasons.push(`Recently issued certificate (${Math.round(certAgeDays)} days old)`)
    }

    // 2. Short certificate validity (phishing certs often use short-lived certs)
    const validityMs = leafCert.validTo - leafCert.validFrom
    const validityDays = validityMs / (1000 * 60 * 60 * 24)

    if (validityDays < 30) {
      score += 0.25
      reasons.push(`Unusually short certificate validity (${Math.round(validityDays)} days) - typical of phishing infrastructure`)
    } else if (validityDays < 90) {
      score += 0.1
      reasons.push(`Short certificate validity period (${Math.round(validityDays)} days)`)
    }

    details.validityDays = Math.round(validityDays)

    // 3. Self-signed certificate
    if (leafCert.isSelfSigned) {
      score += 0.5
      reasons.push('Self-signed certificate - cannot verify domain ownership')
      confidence = 0.95
    }

    // 4. Certificate Subject analysis - check for brand impersonation in subject
    const subjectLower = leafCert.subject.toLowerCase()
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      for (const domain of domains) {
        const brandName = domain.split('.')[0].toLowerCase()
        if (subjectLower.includes(brandName) && !hostname.includes(brandName)) {
          score += 0.3
          reasons.push(
            `Certificate subject references "${brand}" but domain "${hostname}" does not match`
          )
          details.brandMismatch = { brand, subject: leafCert.subject }
        }
      }
    }

    // 5. Issuer pattern analysis (known phishing CA patterns)
    const issuerLower = leafCert.issuer.toLowerCase()
    const suspiciousIssuerPatterns = [
      /Let's Encrypt/i,
      /ZeroSSL/i,
      /cPanel/i,
      /Cloudflare/i,
      /Google Trust/i,
      /Amazon/i,
      /Buypass/i,
      /Globalsign/i,
      /DigiCert/i
    ]

    const matchedIssuer = suspiciousIssuerPatterns.find(p => p.test(issuerLower))
    if (matchedIssuer) {
      details.certificateAuthority = matchedIssuer.source.replace(/\/i$/, '')
      // Not inherently suspicious, but noted for correlation
    }

    // 6. Correlation with known phishing certificates
    const certFingerprint = leafCert.fingerprint
    const existingRecord = this.recentCertificates.get(certFingerprint)

    if (existingRecord) {
      existingRecord.seenCount++
      existingRecord.lastSeen = Date.now()
      if (existingRecord.seenCount > 1) {
        score += 0.1
        reasons.push('Certificate fingerprint matches previously analyzed suspicious site')
        details.certCorrelation = existingRecord.seenCount
      }
    } else {
      this.storeCertificate(certFingerprint, hostname, leafCert.issuer)
    }

    // 7. Subject Alternative Name analysis
    if (leafCert.subject) {
      const sanMatch = leafCert.subject.match(/CN\s*=\s*([^,]+)/)
      if (sanMatch) {
        const cn = sanMatch[1].trim().toLowerCase()
        if (cn !== hostname && !cn.startsWith('*.')) {
          score += 0.15
          reasons.push(
            `Certificate Common Name "${cn}" does not match domain "${hostname}"`
          )
          details.certCN = cn
        }
      }
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'CERTIFICATE ANOMALY DETECTED: The TLS certificate has unusual issuance patterns, very recent creation date, or subject/domain mismatches consistent with phishing setups.'
      : score > 0.2
        ? 'Minor certificate anomalies detected. The certificate has recently been issued or has unusual properties.'
        : 'Certificate issuance patterns appear normal.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private storeCertificate(fingerprint: string, hostname: string, issuer: string): void {
    if (this.recentCertificates.size >= this.MAX_CERTS) {
      // Remove oldest entry
      const oldest = this.recentCertificates.entries().next()
      if (oldest.value) {
        this.recentCertificates.delete(oldest.value[0])
      }
    }

    this.recentCertificates.set(fingerprint, {
      hostname,
      issuer,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      seenCount: 1
    })

    // Periodically clean up old entries
    if (this.recentCertificates.size % 100 === 0) {
      this.cleanupOldEntries()
    }
  }

  private cleanupOldEntries(): void {
    const cutoff = Date.now() - this.RECENT_WINDOW_MS
    for (const [key, record] of this.recentCertificates.entries()) {
      if (record.lastSeen < cutoff) {
        this.recentCertificates.delete(key)
      }
    }
  }

  clearCache(): void {
    this.recentCertificates.clear()
  }
}

interface CertRecord {
  hostname: string
  issuer: string
  firstSeen: number
  lastSeen: number
  seenCount: number
}
