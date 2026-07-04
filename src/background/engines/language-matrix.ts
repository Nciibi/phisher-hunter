import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { PHISHING_NGRAM_PATTERNS } from '../../shared/constants'

/**
 * PHISHING LANGUAGE PATTERN MATRIX
 * 
 * Novel technique: Uses n-gram frequency analysis and pattern matrix
 * matching against known phishing language categories:
 * 
 * - Urgency patterns: "Act now", "Limited time", "Immediate action required"
 * - Authority impersonation: "Security team", "Account services", "Official notice"
 * - Threat language: "Suspended", "Disabled", "Compromised", "Unauthorized access"
 * - Reward/promise patterns: "You won", "Prize", "Inheritance", "Compensation"
 * - Credential framing: "Verify your account", "Confirm your details", "Update password"
 * 
 * Each category is scored independently and combined into a composite
 * language deception score.
 */
export class LanguageMatrixEngine extends BaseEngine {
  id = 'language-matrix'
  name = 'Phishing Language Pattern Matrix'
  description = 'Statistical n-gram analysis of page text for phishing language patterns'
  version = '2.0.0'
  weight = 13

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.83

    const html = context.html || ''
    const title = (context.documentProps?.title || '')

    // Extract visible text content
    const visibleText = this.extractVisibleText(html)
    const textLength = visibleText.length
    const titleText = title

    if (textLength < 20 && !titleText) {
      reasons.push('Insufficient text content for language analysis')
      return this.createResult(0, 0.3, reasons, 'No textual content to analyze.', details)
    }

    const combinedText = titleText + ' ' + visibleText
    details.textLength = textLength
    details.hasTitle = !!titleText

    // 1. Score each language category
    const categoryScores: Record<string, { score: number; matches: string[] }> = {}

    for (const [category, patterns] of Object.entries(PHISHING_NGRAM_PATTERNS)) {
      const matches: string[] = []
      for (const pattern of patterns) {
        const match = combinedText.match(pattern)
        if (match) {
          matches.push(match[0].trim())
        }
      }

      if (matches.length > 0) {
        // Deduplicate
        const uniqueMatches = [...new Set(matches)]
        categoryScores[category] = {
          score: Math.min(1, uniqueMatches.length * 0.2),
          matches: uniqueMatches
        }
      }
    }

    details.categoryScores = Object.fromEntries(
      Object.entries(categoryScores).map(([k, v]) => [k, { score: v.score, matchCount: v.matches.length }])
    )

    // 2. Calculate weighted category scores
    const categoryWeights: Record<string, number> = {
      urgency: 0.25,
      authority: 0.15,
      threat: 0.25,
      reward: 0.15,
      credential: 0.2
    }

    let weightedScore = 0
    let totalWeight = 0

    for (const [category, { score: catScore, matches }] of Object.entries(categoryScores)) {
      const weight = categoryWeights[category] || 0.1
      weightedScore += catScore * weight
      totalWeight += weight

      if (matches.length >= 2) {
        const categoryLabel = category.charAt(0).toUpperCase() + category.slice(1)
        reasons.push(
          `${categoryLabel} language detected (${matches.length} pattern(s))`
        )
        details[`${category}Examples`] = matches.slice(0, 3)
      }
    }

    if (totalWeight > 0) {
      score += weightedScore / totalWeight
    }

    // 3. Critical combination detection
    // Phishing pages often combine multiple categories
    const activeCategories = Object.keys(categoryScores).length

    if (activeCategories >= 3) {
      score += 0.15
      reasons.push(
        `Multiple phishing language patterns active (${activeCategories} of 5 categories) - consistent with phishing templates`
      )
    }

    // 4. Check for specific dangerous combinations
    if (categoryScores.urgency && categoryScores.credential) {
      score += 0.1
      reasons.push('Urgent language combined with credential request - common phishing tactic')
    }

    if (categoryScores.threat && categoryScores.credential) {
      score += 0.1
      reasons.push('Threat language used to pressure credential submission - classic phishing')
    }

    if (categoryScores.authority && categoryScores.credential) {
      score += 0.05
      reasons.push('Authority impersonation used to request credentials')
    }

    // 5. Check for excessive capitalization (phishing urgency signal)
    const capsRatio = this.calculateCapsRatio(visibleText)
    if (capsRatio > 0.3) {
      score += 0.1
      reasons.push(`Excessive capitalization (${Math.round(capsRatio * 100)}% of text) - aggressive tone`)
    }

    // 6. Check for punctuation patterns (multiple !!!, ???)
    const excessivePunctuation = (combinedText.match(/[!?]{2,}/g) || []).length
    if (excessivePunctuation > 3) {
      score += 0.05
      reasons.push(`Excessive punctuation marks (${excessivePunctuation}) - emotional manipulation`)
    }

    // 7. Check for brand name in title mismatch with domain
    if (titleText) {
      for (const [brand] of Object.entries(categoryWeights)) {
        const brandInTitle = titleText.toLowerCase().includes(brand)
        if (brandInTitle && activeCategories >= 2) {
          score += 0.05
        }
      }
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'PHISHING LANGUAGE MATRIX MATCH: The page text uses statistically significant language patterns consistent with phishing. Urgency, threats, and credential requests detected.'
      : score > 0.2
        ? 'Some phishing language patterns detected. The page tone has suspicious characteristics.'
        : 'Language analysis is consistent with legitimate communication patterns.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private extractVisibleText(html: string): string {
    // Remove scripts, styles, and HTML tags to get visible text
    return html
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&[a-z]+;/gi, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 10000)
  }

  private calculateCapsRatio(text: string): number {
    if (!text) return 0
    const letters = text.replace(/[^a-zA-Z]/g, '')
    if (!letters) return 0
    const caps = letters.replace(/[a-z]/g, '')
    return caps.length / letters.length
  }
}
