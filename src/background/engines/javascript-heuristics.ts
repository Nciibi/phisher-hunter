import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

export class JavascriptHeuristicsEngine extends BaseEngine {
  id = 'javascript-heuristics'
  name = 'JavaScript Behavioral Heuristics'
  description = 'Analyzes JavaScript for malicious behavioral patterns'
  version = '1.0.0'
  weight = 8

  private readonly SUSPICIOUS_PATTERNS = [
    { pattern: /document\.location\s*=/i, weight: 0.3, desc: 'Redirect via document.location assignment' },
    { pattern: /window\.location\s*=/i, weight: 0.3, desc: 'Redirect via window.location assignment' },
    { pattern: /document\.write\s*\(/i, weight: 0.1, desc: 'Dynamic document writing' },
    { pattern: /\.submit\s*\(/i, weight: 0.15, desc: 'Programmatic form submission' },
    { pattern: /document\.forms\[/i, weight: 0.1, desc: 'Accessing forms by index' },
    { pattern: /getElementById.*password/i, weight: 0.2, desc: 'Accessing password fields by ID' },
    { pattern: /onerror\s*=/i, weight: 0.1, desc: 'Error handler override' },
    { pattern: /onload\s*=/i, weight: 0.05, desc: 'Onload handler' },
    { pattern: /createElement\s*\(\s*['"]iframe['"]/i, weight: 0.2, desc: 'Dynamic iframe creation' },
    { pattern: /createElement\s*\(\s*['"]form['"]/i, weight: 0.15, desc: 'Dynamic form creation' },
    { pattern: /addEventListener\s*\(\s*['"]submit['"]/i, weight: 0.15, desc: 'Form submit listener' },
    { pattern: /\.value\s*=/i, weight: 0.05, desc: 'Direct value assignments' },
    { pattern: /atob\s*\(/i, weight: 0.15, desc: 'Base64 decoding (potential obfuscation)' },
    { pattern: /eval\s*\(/i, weight: 0.3, desc: 'Eval usage (code execution)' },
    { pattern: /Function\s*\(/i, weight: 0.2, desc: 'Dynamic function creation' },
    { pattern: /setTimeout\s*\(\s*['"]/i, weight: 0.1, desc: 'String-based setTimeout' },
    { pattern: /fromCharCode/i, weight: 0.1, desc: 'Character code obfuscation' },
    { pattern: /\\x[0-9a-f]{2}/i, weight: 0.1, desc: 'Hex-encoded strings' },
    { pattern: /\\u[0-9a-f]{4}/i, weight: 0.05, desc: 'Unicode-encoded strings' },
    { pattern: /keylog/i, weight: 0.5, desc: 'Keylogging reference' },
    { pattern: /addEventListener\s*\(\s*['"]key/i, weight: 0.3, desc: 'Keyboard event listener' },
    { pattern: /navigator\.userAgent/i, weight: 0.05, desc: 'User agent detection' },
    { pattern: /cookie\s*=/i, weight: 0.1, desc: 'Cookie manipulation' },
    { pattern: /document\.cookie/i, weight: 0.1, desc: 'Cookie access' },
    { pattern: /XMLHttpRequest/i, weight: 0.05, desc: 'AJAX request' },
    { pattern: /fetch\s*\(/i, weight: 0.05, desc: 'Fetch API usage' },
    { pattern: /window\.open\s*\(/i, weight: 0.1, desc: 'Window open' },
    { pattern: /history\.pushState/i, weight: 0.05, desc: 'History manipulation' },
  ]

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.6

    const scripts = context.scripts || []
    details.scriptCount = scripts.length

    if (scripts.length === 0) {
      reasons.push('No JavaScript detected on page')
      confidence = 0.3
      return this.createResult(score, confidence, reasons, 'No scripts to analyze.', details)
    }

    if (scripts.length > 50) {
      score += 0.1
      reasons.push(`Unusually large number of scripts (${scripts.length})`)
    }

    const combinedScripts = scripts.join(' ')
    const findings: Array<{ pattern: string; desc: string; weight: number }> = []

    for (const check of this.SUSPICIOUS_PATTERNS) {
      const matches = combinedScripts.match(check.pattern)
      if (matches) {
        findings.push({
          pattern: check.pattern.source.slice(0, 40),
          desc: check.desc,
          weight: check.weight
        })
      }
    }

    details.findings = findings

    const criticalFindings = findings.filter(f => f.weight >= 0.3)
    const moderateFindings = findings.filter(f => f.weight >= 0.15 && f.weight < 0.3)
    const minorFindings = findings.filter(f => f.weight < 0.15)

    if (criticalFindings.length > 0) {
      score += Math.min(0.6, criticalFindings.length * 0.2)
      for (const finding of criticalFindings.slice(0, 5)) {
        reasons.push(`Critical pattern: ${finding.desc}`)
      }
    }

    if (moderateFindings.length > 0) {
      score += Math.min(0.3, moderateFindings.length * 0.08)
      for (const finding of moderateFindings.slice(0, 3)) {
        reasons.push(`Suspicious pattern: ${finding.desc}`)
      }
    }

    if (minorFindings.length > 0) {
      score += Math.min(0.15, minorFindings.length * 0.03)
    }

    const suspiciousScripts = scripts.filter(s =>
      this.SUSPICIOUS_PATTERNS.some(p => p.pattern.test(s))
    )
    if (suspiciousScripts.length > 0) {
      details.suspiciousScriptCount = suspiciousScripts.length
      confidence = Math.min(0.9, 0.6 + suspiciousScripts.length * 0.05)
    }

    const inlineScriptCount = scripts.filter(s => !s.includes('src=')).length
    details.inlineScriptCount = inlineScriptCount
    if (inlineScriptCount > 20) {
      score += 0.1
      reasons.push(`Large number of inline scripts (${inlineScriptCount})`)
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'The JavaScript on this page exhibits patterns commonly associated with phishing and credential harvesting.'
      : score > 0.2
        ? 'Some suspicious JavaScript patterns detected. Proceed with caution.'
        : 'JavaScript behavior appears normal.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
