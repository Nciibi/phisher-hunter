import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { CSS_DECEPTION_PATTERNS } from '../../shared/constants'

/**
 * CSS DECEPTION ANALYSIS
 * 
 * Novel technique: Analyzes CSS stylesheets and inline styles for
 * visual deception techniques commonly used in phishing:
 * 
 * - Overlay techniques: Full-viewport fixed/absolute elements with
 *   high z-index that capture clicks or display fake content
 * - Invisible elements: Opacity: 0, visibility: hidden tricks
 * - Text hiding: text-indent: -9999px to hide real text
 * - Fake security seals: Positioned badge images
 * - Clickjacking: iframe overlays with opacity/position tricks
 * - CSS-based brand impersonation: Exact color, font, and styling
 *   matches to legitimate brands
 * - Fake URL bars: Positioned fixed elements at the top that look
 *   like browser chrome
 */
export class CssDeceptionEngine extends BaseEngine {
  id = 'css-deception'
  name = 'CSS Deception Analysis'
  description = 'Scans CSS for visual deception techniques (overlays, clickjacking, fake chrome)'
  version = '2.0.0'
  weight = 10

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.82

    const html = context.html || ''
    const styles = this.extractCSS(html)
    details.styleCount = styles.length
    details.totalCSSText = styles.join(' ').length

    // 1. Check for CSS deception patterns
    const findings: Array<{ name: string; weight: number; count: number }> = []
    const combinedCSS = styles.join(' ')

    for (const { pattern, weight, name } of CSS_DECEPTION_PATTERNS) {
      const matches = combinedCSS.match(pattern)
      if (matches) {
        findings.push({ name, weight, count: matches.length })
      }
    }

    details.cssFindings = findings

    // Score based on findings
    for (const finding of findings) {
      score += Math.min(finding.weight, finding.weight * finding.count * 0.5)
    }

    if (findings.length > 0) {
      const criticalFindings = findings.filter(f => f.weight >= 0.15)
      if (criticalFindings.length > 0) {
        reasons.push(
          `CSS deception detected: ${criticalFindings.map(f => f.name.replace(/-/g, ' ')).join(', ')}`
        )
      }
    }

    // 2. Check for full-viewport overlays (common in phishing)
    const overlayPatterns = [
      /position\s*:\s*fixed[^}]*?(?:top\s*:\s*0|left\s*:\s*0)[^}]*?(?:width\s*:\s*100%|height\s*:\s*100%)/i,
      /position\s*:\s*absolute[^}]*?z-index\s*:\s*\d{4,}[^}]*?(?:top\s*:\s*0|left\s*:\s*0)/i,
      /width\s*:\s*100vw[^}]*?height\s*:\s*100vh/i
    ]

    const overlayMatches = overlayPatterns.filter(p => p.test(combinedCSS))
    if (overlayMatches.length > 0) {
      score += Math.min(0.3, overlayMatches.length * 0.1)
      reasons.push(
        `Full-viewport overlay detected (${overlayMatches.length} pattern(s)) - possible clickjacking`
      )
      details.overlayDetected = true
    }

    // 3. Check for fake URL bar / browser chrome simulation
    const fakeChromePatterns = [
      /position\s*:\s*fixed[^}]*?top\s*:\s*0[^}]*?height\s*:\s*(?:30|40|50|60)px/i,
      /z-index\s*:\s*(?:2147483647|99999|999999)[^}]*?background[^}]*?white/i,
      /position\s*:\s*fixed[^}]*?(?:top|bottom)\s*:\s*0[^}]*?width\s*:\s*100%/i
    ]

    const chromeMatches = fakeChromePatterns.filter(p => p.test(combinedCSS))
    if (chromeMatches.length > 0) {
      score += 0.25
      reasons.push('Fake browser chrome/URL bar detected - site may be spoofing the browser UI')
      details.fakeChromeDetected = true
    }

    // 4. Check for inline style deception
    const inlineStyles = this.extractInlineStyles(html)
    details.inlineStyleCount = inlineStyles.length

    for (const style of inlineStyles) {
      if (/opacity\s*:\s*0(?:\s*!important)?/i.test(style)) {
        score += 0.1
        reasons.push('Element hidden via inline opacity:0')
      }
      if (/display\s*:\s*none/i.test(style) && /form|input|password/i.test(html.slice(
        Math.max(0, html.indexOf(style) - 200),
        html.indexOf(style) + 200
      ))) {
        score += 0.15
        reasons.push('Form-related element hidden via display:none - suspicious')
      }
    }

    // 5. Check for CSS @import from external domains (phishkits often load CSS remotely)
    const importPattern = /@import\s+(?:url\s*\(\s*)?['"]https?:\/\/([^'"\/) ]+)/gi
    let importMatch: RegExpExecArray | null
    while ((importMatch = importPattern.exec(combinedCSS)) !== null) {
      const importDomain = importMatch[1]
      if (importDomain !== context.hostname) {
        score += 0.1
        reasons.push(`CSS imports from external domain "${importDomain}"`)
        details.externalCSS = importDomain
      }
    }

    // 6. Check for exact brand color reproduction (fake brand pages)
    const brandColorPatterns = [
      /#4285f4/i,  // Google Blue
      /#34a853/i,  // Google Green
      /#ea4335/i,  // Google Red
      /#fbbc04/i,  // Google Yellow
      /#0078d4/i,  // Microsoft Blue
      /#ff9900/i,  // Amazon Orange
      /#00aeef/i,  // PayPal Blue
      /#1877f2/i,  // Facebook Blue
      /#1da1f2/i,  // Twitter Blue
      /#a4c639/i,  // Android Green
      /rgb\(66,133,244\)/i,
      /rgb\(52,168,83\)/i,
      /rgb\(234,67,53\)/i,
      /rgb\(251,188,4\)/i
    ]

    const brandColorMatches = brandColorPatterns.filter(p => p.test(combinedCSS))
    if (brandColorMatches.length >= 3) {
      score += 0.15
      reasons.push(`Exact brand color codes detected (${brandColorMatches.length} matches) - page mimics brand styling`)
      details.brandColors = brandColorMatches.length
    }

    // 7. Check for CSS keylogging (invisible input tracking)
    const keylogCSSPatterns = [
      /position[\s\S]{0,50}?absolute[\s\S]{0,200}?opacity[\s\S]{0,50}?0/i,
      /z-index[\s\S]{0,50}?-1[\s\S]{0,200}?position[\s\S]{0,50}?absolute/i
    ]

    if (keylogCSSPatterns.some(p => p.test(combinedCSS))) {
      score += 0.1
      reasons.push('CSS pattern matches invisible input overlay technique')
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'CSS DECEPTION DETECTED: This page uses CSS techniques commonly employed by phishing sites to deceive users. Overlays, hidden elements, and fake browser chrome detected.'
      : score > 0.2
        ? 'Some CSS anomalies detected. The page styling has minor deceptive characteristics.'
        : 'CSS analysis passed. No deception techniques detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private extractCSS(html: string): string[] {
    const styles: string[] = []

    // Extract <style> blocks
    const styleRegex = /<style[^>]*>([\s\S]*?)<\/style>/gi
    let match: RegExpExecArray | null
    while ((match = styleRegex.exec(html)) !== null) {
      if (match[1]) styles.push(match[1])
    }

    // Extract inline style attributes
    const inlineRegex = /style\s*=\s*["']([^"']+)["']/gi
    while ((match = inlineRegex.exec(html)) !== null) {
      if (match[1]) styles.push(match[1])
    }

    return styles
  }

  private extractInlineStyles(html: string): string[] {
    const styles: string[] = []
    const regex = /style\s*=\s*["']([^"']+)["']/gi
    let match: RegExpExecArray | null
    while ((match = regex.exec(html)) !== null) {
      if (match[1]) styles.push(match[1])
    }
    return styles
  }
}
