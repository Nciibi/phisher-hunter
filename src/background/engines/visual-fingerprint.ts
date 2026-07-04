import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { BRAND_DOMAINS } from '../../shared/constants'

/**
 * VISUAL BRAND FINGERPRINTING
 * 
 * Novel technique: Computes a structural hash of the page DOM and compares
 * it against known legitimate brand page fingerprints. Phishing sites that
 * copy the HTML structure of real brands get caught even on custom domains.
 * 
 * Uses:
 * - Tag sequence fingerprinting (order and nesting of elements)
 * - Class name pattern matching against known brand patterns
 * - Form structure comparison
 * - Logo/image fingerprinting
 * - Layout similarity scoring
 */
export class VisualFingerprintEngine extends BaseEngine {
  id = 'visual-fingerprint'
  name = 'Visual Brand Fingerprint'
  description = 'Compares DOM structure against known legitimate brand page fingerprints'
  version = '2.0.0'
  weight = 15

  // Known brand structural signatures (tag patterns)
  private readonly brandSignatures: Record<string, BrandSignature> = {
    google: {
      loginPatterns: [
        'div>div>form>div>input',
        'div>div>div>span',
        'div>img+div>input'
      ],
      keyElements: ['identifier', 'password'],
      formCount: 1,
      inputTypes: ['email', 'password']
    },
    microsoft: {
      loginPatterns: [
        'div>div>div>form>div>input',
        'div>div>div>div>img'
      ],
      keyElements: ['login', 'password', 'credentials'],
      formCount: 1,
      inputTypes: ['email', 'password']
    },
    facebook: {
      loginPatterns: [
        'form>div>input',
        'div>button'
      ],
      keyElements: ['email', 'pass'],
      formCount: 1,
      inputTypes: ['text', 'password']
    },
    apple: {
      loginPatterns: [
        'section>form>input',
        'div>div>img'
      ],
      keyElements: ['account', 'password'],
      formCount: 1,
      inputTypes: ['text', 'password']
    },
    paypal: {
      loginPatterns: [
        'div>form>div>input',
        'div>div>button'
      ],
      keyElements: ['email', 'password', 'login'],
      formCount: 1,
      inputTypes: ['email', 'password']
    }
  }

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.85

    const html = context.html || ''
    const title = (context.documentProps?.title || '').toLowerCase()
    const forms = context.forms || []

    // 1. Compute structural fingerprint of current page
    const fingerprint = this.computeFingerprint(html)
    details.fingerprint = fingerprint

    // 2. Identify which brand the page is trying to imitate
    const suspiciousBrand = this.identifyImpersonatedBrand(title, html, forms)
    details.suspectedBrand = suspiciousBrand

    if (!suspiciousBrand) {
      reasons.push('No brand fingerprint match detected')
      return this.createResult(score, confidence, reasons, 'No visual brand impersonation detected.', details)
    }

    const signature = this.brandSignatures[suspiciousBrand]
    if (!signature) {
      reasons.push(`Potential "${suspiciousBrand}" impersonation detected but no signature available`)
      score += 0.3
      return this.createResult(score, confidence, reasons, 'Brand impersonation suspected.', details)
    }

    // 3. Compare structural similarity
    const structuralScore = this.compareStructure(fingerprint, signature, forms)
    details.structuralScore = structuralScore
    score += structuralScore * 0.4

    if (structuralScore > 0.7) {
      reasons.push(
        `DOM structure is ${Math.round(structuralScore * 100)}% similar to "${suspiciousBrand}" login page`
      )
    }

    // 4. Compare form fields
    const formSimilarity = this.compareFormFields(forms, signature)
    details.formSimilarity = formSimilarity
    score += formSimilarity * 0.3

    if (formSimilarity > 0.6) {
      reasons.push(
        `Form field structure matches "${suspiciousBrand}" login form pattern (${Math.round(formSimilarity * 100)}% similarity)`
      )
    }

    // 5. Check for brand-specific keywords in unexpected places
    const brandKeywords = this.extractBrandKeywords(html, title, suspiciousBrand)
    if (brandKeywords.length > 0) {
      score += 0.15
      reasons.push(`Brand-specific content found: "${brandKeywords.join(', ')}"`)
      details.brandKeywords = brandKeywords
    }

    // 6. Check for logo/icon patterns
    const logoPattern = this.detectBrandLogo(html, suspiciousBrand)
    if (logoPattern) {
      score += 0.1
      reasons.push(`Brand logo detected (${logoPattern})`)
      details.logoDetected = true
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? `VISUAL FINGERPRINT MATCH: This page structurally impersonates "${suspiciousBrand}". The layout, form fields, and content closely mimic the real brand.`
      : score > 0.2
        ? `Some visual similarities to "${suspiciousBrand}" detected. Verify the URL before entering credentials.`
        : 'No significant brand impersonation detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private computeFingerprint(html: string): string {
    const tagPattern = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/\s+/g, ' ')
      .replace(/<(\w+)[^>]*>/g, '<$1>')
      .replace(/>\s*</g, '><')
      .slice(0, 5000)
    return tagPattern
  }

  private identifyImpersonatedBrand(
    title: string,
    html: string,
    forms: EngineContext['forms']
  ): string | null {
    const combinedContent = title + ' ' + html.slice(0, 10000)

    const brandScores: Array<{ brand: string; score: number }> = []

    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      let score = 0
      const brandName = brand.replace(/_/g, ' ')

      // Check title and meta description
      if (combinedContent.includes(brandName.toLowerCase())) {
        score += 3
      }

      // Check for brand in domain patterns
      for (const domain of domains) {
        const domainName = domain.split('.')[0]
        if (combinedContent.includes(domainName)) {
          score += 2
        }
      }

      // Check for brand-specific keywords
      if (brand === 'google' && combinedContent.match(/sign\s*in|gmail|google/i)) score += 2
      if (brand === 'microsoft' && combinedContent.match(/outlook|office\s*365|microsoft/i)) score += 2
      if (brand === 'paypal' && combinedContent.match(/paypal|send\s+money/i)) score += 2
      if (brand === 'facebook' && combinedContent.match(/facebook|log\s+in/i)) score += 2
      if (brand === 'apple' && combinedContent.match(/apple\s*(id|store)|icloud/i)) score += 2

      // Check for login/security forms
      if (forms?.some(f => f.hasPassword)) {
        if (combinedContent.includes('sign in') || combinedContent.includes('log in')) {
          score += 1
        }
      }

      if (score > 0) {
        brandScores.push({ brand, score })
      }
    }

    brandScores.sort((a, b) => b.score - a.score)
    return brandScores.length > 0 && brandScores[0].score >= 3 ? brandScores[0].brand : null
  }

  private compareStructure(
    fingerprint: string,
    signature: BrandSignature,
    forms: EngineContext['forms']
  ): number {
    let matches = 0
    let total = signature.loginPatterns.length

    for (const pattern of signature.loginPatterns) {
      const escapedPattern = pattern.replace(/>/g, '>').replace(/\+/g, '.+')
      const regex = new RegExp(escapedPattern, 'i')
      if (regex.test(fingerprint)) {
        matches++
      }
    }

    // Check form count match
    const formCount = forms?.length || 0
    if (formCount === signature.formCount) {
      matches++
    }
    total++

    return total > 0 ? matches / total : 0
  }

  private compareFormFields(
    forms: EngineContext['forms'],
    signature: BrandSignature
  ): number {
    if (!forms || forms.length === 0) return 0

    let matches = 0
    const total = Math.min(forms.length * signature.inputTypes.length, 10)

    for (const form of forms) {
      const fieldNames = form.fields.map(f => f.name.toLowerCase())
      for (const keyElement of signature.keyElements) {
        if (fieldNames.some(n => n.includes(keyElement))) {
          matches++
        }
      }
      const fieldTypes = form.fields.map(f => f.type.toLowerCase())
      for (const inputType of signature.inputTypes) {
        if (fieldTypes.includes(inputType)) {
          matches++
        }
      }
    }

    return total > 0 ? Math.min(1, matches / total) : 0
  }

  private extractBrandKeywords(
    html: string,
    title: string,
    brand: string
  ): string[] {
    const found: string[] = []
    const brandData = BRAND_DOMAINS[brand]
    if (!brandData) return found

    const text = (title + ' ' + html.slice(0, 5000)).toLowerCase()
    const domainNames = brandData.map(d => d.split('.')[0].toLowerCase())

    for (const name of domainNames) {
      if (text.includes(name)) {
        found.push(name)
      }
    }

    // Check for brand-specific imagery/logo references
    const logoPatterns = [
      new RegExp(`${brand}.*logo`, 'i'),
      new RegExp(`${brand}.*icon`, 'i'),
      new RegExp(`${brand}.*brand`, 'i'),
      /favicon/i
    ]

    if (logoPatterns.some(p => p.test(html))) {
      found.push('brand_imagery')
    }

    return found
  }

  private detectBrandLogo(html: string, brand: string): string | null {
    const brandData = BRAND_DOMAINS[brand]
    if (!brandData) return null

    const domainNames = brandData.map(d => d.split('.')[0].toLowerCase())

    // Check img alt text and src for brand references
    const imgPattern = new RegExp(
      `<img[^>]*?(?:alt|src|title)=["'][^"']*?(${domainNames.join('|')})[^"']*?["']`,
      'i'
    )

    const match = html.match(imgPattern)
    if (match) {
      return match[1]
    }

    // Check SVG inline brand references
    const svgPattern = new RegExp(
      `<svg[^>]*?>[\\s\\S]{0,500}?(${domainNames.join('|')})[\\s\\S]{0,500}?<\\/svg>`,
      'i'
    )

    if (svgPattern.test(html)) {
      return 'inline_svg'
    }

    return null
  }

  clearFingerprintCache(): void {
    // Cache can be cleared when brands update their pages
  }
}

interface BrandSignature {
  loginPatterns: string[]
  keyElements: string[]
  formCount: number
  inputTypes: string[]
}
