import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

/**
 * INTERACTIVE HONEYPOT DETECTION
 * 
 * Novel technique: Detects hidden interactive elements that serve as
 * honeypots for bots and automated scrapers. These elements are:
 * - Invisible to human users (offscreen, zero-size, or hidden)
 * - Detectable and interactive to JavaScript/bots
 * - Often contain decoy content or tracking mechanisms
 * 
 * Phishing kits sometimes include honeypots to:
 * - Detect security researchers
 * - Track bot visits
 * - fingerprint visitors
 * - Bypass automated analysis tools
 * 
 * This engine detects sites that USE honeypots (potential phishers
 * trying to evade detection) as well as sites that ARE honeypots
 * (decoy phishing pages).
 */
export class InteractiveHoneypotEngine extends BaseEngine {
  id = 'interactive-honeypot'
  name = 'Interactive Honeypot Detection'
  description = 'Detects hidden interactive elements and honeypot techniques used by phishers'
  version = '2.0.0'
  weight = 7

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.75

    const html = context.html || ''
    const forms = context.forms || []
    const iframes = context.iframes || []

    // 1. Detect hidden form fields commonly used as honeypots
    for (const form of forms) {
      const hiddenFields = form.fields.filter(f => f.isHidden)
      const honeypotFields = hiddenFields.filter(f =>
        /^(website|url|homepage|message|comment|_hp_|_honey|_decoy)/i.test(f.name)
      )

      if (honeypotFields.length > 0) {
        score += 0.25
        reasons.push(
          `Honeypot form field detected: "${honeypotFields[0].name}" - field invisible to users but accessible to scripts`
        )
        details.honeypotField = honeypotFields[0].name
      }

      // Hidden fields with suspicious names that collect data
      const trackingHiddenFields = hiddenFields.filter(f =>
        /^(utm_|_ga|_fb|track|fingerprint|session_id|visitor)/i.test(f.name) &&
        form.isExternal
      )

      if (trackingHiddenFields.length > 0) {
        score += 0.15
        reasons.push(`Form contains ${trackingHiddenFields.length} tracking-related hidden fields`)
      }
    }

    // 2. Detect invisible iframes used as tracking/deception honeypots
    const hiddenIframes = iframes.filter(f => f.isHidden)
    const honeypotIframes = hiddenIframes.filter(f => {
      const dims = [parseInt(f.width), parseInt(f.height)].filter(d => !isNaN(d))
      return dims.some(d => d <= 1) || dims.every(d => d === 0)
    })

    if (honeypotIframes.length > 0) {
      score += Math.min(0.3, honeypotIframes.length * 0.1)
      reasons.push(
        `${honeypotIframes.length} honeypot iframe(s) detected (1x1px or 0x0px) - possible tracking/fingerprinting`
      )
    }

    // 3. Detect invisible links (honeypot links for bot detection)
    const invisibleLinkPatterns = [
      /<a[^>]*style=["'][^"']*?(?:display\s*:\s*none|opacity\s*:\s*0)[^"']*?["'][^>]*>.*?<\/a>/gi,
      /<a[^>]*style=["'][^"']*?(?:position\s*:\s*absolute[^"']*?(?:left|top)\s*:\s*-\d+)/gi,
      /<a[^>]*hidden[^>]*>.*?<\/a>/gi
    ]

    let invisibleLinkCount = 0
    for (const pattern of invisibleLinkPatterns) {
      const matches = html.match(pattern)
      if (matches) invisibleLinkCount += matches.length
    }

    if (invisibleLinkCount > 0) {
      score += Math.min(0.2, invisibleLinkCount * 0.05)
      reasons.push(
        `${invisibleLinkCount} invisible link(s) detected - honeypot for bot/crawler detection`
      )
      details.invisibleLinkCount = invisibleLinkCount
    }

    // 4. Detect CSS-based honeypot techniques
    const cssHoneypotPatterns = [
      /position\s*:\s*absolute[^}]*?(?:left|top)\s*:\s*-\d{4,}/gi,  // Offscreen positioning
      /clip:\s*rect\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)/gi,      // Clip:rect(0,0,0,0)
      /overflow:\s*hidden;[^}]*?(?:width|height)\s*:\s*0/gi,        // Hidden overflow
      /text-indent:\s*-\d{4,}/gi                                     // Offscreen text
    ]

    let cssHoneypotCount = 0
    for (const pattern of cssHoneypotPatterns) {
      const matches = html.match(pattern)
      if (matches) cssHoneypotCount += matches.length
    }

    if (cssHoneypotCount > 0) {
      score += Math.min(0.15, cssHoneypotCount * 0.03)
      reasons.push(`CSS honeypot techniques detected (${cssHoneypotCount} occurrences)`)
    }

    // 5. Detect JavaScript honeypot/decoy elements
    const jsHoneypotPatterns = [
      /getElementById\s*\(\s*['"]honeypot['"]\s*\)/i,
      /getElementById\s*\(\s*['"]_hp_/i,
      /getElementById\s*\(\s*['"]decoy/i,
      /\.value\s*!==\s*['']['"]\s*&&/i,  // Checking if honeypot field was filled
      /if\s*\([^)]*\.value\s*!==\s*['']['"]\s*\)\s*\{[\s\S]{0,200}?return/i
    ]

    const scripts = context.scripts || []
    const combinedScripts = scripts.join(' ')

    const jsHoneypotMatches = jsHoneypotPatterns.filter(p => p.test(combinedScripts))
    if (jsHoneypotMatches.length > 0) {
      score += 0.2
      reasons.push('JavaScript honeypot detection logic found - site actively detects automated visitors')
      details.jsHoneypotDetected = true
    }

    // 6. Detect honeypot forms (forms that shouldn't be submitted but are)
    const suspiciousActionForms = forms.filter(f => {
      const action = (f.action || '').toLowerCase()
      return action === '#' || action === '' || action === 'javascript:void(0)'
    })

    if (suspiciousActionForms.length > 0 && forms.some(f => f.hasPassword)) {
      score += 0.1
      reasons.push('Password form with no valid action URL - potential data capture honeypot')
    }

    // 7. Detect timing-based honeypots (slow loading elements)
    // This requires observing load timing, which is done in content script
    // For now, detect scripts that measure timing
    const timingPatterns = [
      /performance\.now\s*\(\)/i,
      /Date\.now\s*\(\)/i,
      /performance\.getEntries/i,
      /loadEventEnd/i
    ]

    const timingMatches = timingPatterns.filter(p => p.test(combinedScripts))
    if (timingMatches.length > 2) {
      score += 0.05
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'HONEYPOT DETECTED: This page employs honeypot techniques to detect automated analysis. This is a common anti-analysis tactic used by sophisticated phishing operations.'
      : score > 0.2
        ? 'Minor honeypot techniques detected. The page has some hidden interactive elements.'
        : 'No honeypot techniques detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
