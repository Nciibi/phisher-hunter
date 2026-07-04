import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { SUSPICIOUS_MUTATION_PATTERNS, SCRIPT_MONITOR_WINDOW_MS } from '../../shared/constants'

/**
 * SCRIPT BEHAVIOR TIME-SERIES ANALYSIS
 * 
 * Novel technique: Analyzes JavaScript behavior patterns over time
 * by examining script content and detecting temporal attack patterns.
 * 
 * Phishing kits often use time-delayed execution to evade detection:
 * - Scripts that wait before modifying forms
 * - Code that triggers on specific user interactions
 * - Delayed overlay/fake content injection
 * - Progressive credential harvesting (field by field)
 * 
 * Also detects:
 * - Event listener stacking on password fields
 * - Form action mutation (changing destination after load)
 * - Content script communication patterns
 * - Data exfiltration via image requests (beaconing)
 */
export class ScriptTimeseriesEngine extends BaseEngine {
  id = 'script-timeseries'
  name = 'Script Behavior Time-series'
  description = 'Temporal analysis of JavaScript patterns for time-delayed phishing execution'
  version = '2.0.0'
  weight = 10

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.78

    const scripts = context.scripts || []
    const combinedScripts = scripts.join(' ')
    const html = context.html || ''

    details.scriptCount = scripts.length

    if (scripts.length === 0) {
      reasons.push('No scripts present for time-series analysis')
      return this.createResult(0, 0.2, reasons, 'No JavaScript to analyze.', details)
    }

    // 1. Detect setTimeout/setInterval usage with form manipulation
    const delayedExecutionPatterns = [
      /setTimeout\s*\([\s\S]{0,500}?(form|input|password|submit)/i,
      /setInterval\s*\([\s\S]{0,500}?(form|input|password|submit)/i,
      /addEventListener\s*\(\s*['"](?:load|DOMContentLoaded)['"][\s\S]{0,1000}?(form|input)/i,
      /window\.onload\s*=[\s\S]{0,500}?(form|input)/i,
      /requestAnimationFrame[\s\S]{0,500}?(form|input)/i
    ]

    const delayedMatches = delayedExecutionPatterns.filter(p => p.test(combinedScripts))
    if (delayedMatches.length > 0) {
      score += Math.min(0.25, delayedMatches.length * 0.08)
      reasons.push(
        `Delayed form manipulation detected (${delayedMatches.length} pattern(s)) - possible time-delayed phishkit`
      )
      details.timedExecution = true
    }

    // 2. Detect event listener stacking on forms
    const listenerStackingPatterns = [
      /addEventListener\s*\(\s*['"](?:click|submit|change|input)['"]\s*,/gi,
      /\.onclick\s*=/gi,
      /\.onsubmit\s*=/gi,
      /\.onchange\s*=/gi,
      /\.oninput\s*=/gi
    ]

    let totalListeners = 0
    for (const pattern of listenerStackingPatterns) {
      const matches = combinedScripts.match(pattern)
      if (matches) totalListeners += matches.length
    }

    if (totalListeners > 5) {
      score += Math.min(0.15, totalListeners * 0.02)
      reasons.push(`Excessive event listeners (${totalListeners}) - possible input interception`)
      details.listenerCount = totalListeners
    }

    // 3. Detect form action mutation
    const formMutationPatterns = [
      /\.action\s*=\s*['"]https?:\/\//i,
      /setAttribute\s*\(\s*['"]action['"]/i,
      /\.action\s*=\s*['"][^'"]*?(?:\.php|\.asp|\.cgi|\.jsp)/i
    ]

    const mutationMatches = formMutationPatterns.filter(p => p.test(combinedScripts))
    if (mutationMatches.length > 0) {
      score += 0.2
      reasons.push('Script dynamically changes form action URL - credentials may be redirected')
      details.formActionMutation = true
    }

    // 4. Detect data exfiltration patterns (beaconing)
    const exfiltrationPatterns = [
      /new\s+Image\(\)[\s\S]{0,200}?\.src\s*=/i,
      /navigator\.sendBeacon/i,
      /XMLHttpRequest[\s\S]{0,300}?\.open[\s\S]{0,100}?POST/i,
      /fetch\s*\(\s*['"]https?:\/\//i,
      /\.src\s*=\s*['"]https?:\/\/[^'"]*?(?:log|track|collect|beacon|pixel)/i
    ]

    const exfilMatches = exfiltrationPatterns.filter(p => p.test(combinedScripts))
    if (exfilMatches.length > 0) {
      score += Math.min(0.2, exfilMatches.length * 0.05)
      details.exfiltrationPatterns = exfilMatches.length
      if (exfilMatches.length >= 2) {
        reasons.push(`Data exfiltration patterns detected (${exfilMatches.length}) - possible data theft`)
      }
    }

    // 5. Detect DOM content overlay/modification after load
    const overlayPatterns = [
      /innerHTML\s*=[\s\S]{0,500}?(?:overlay|modal|popup|warning|alert|banner)/i,
      /insertAdjacentHTML[\s\S]{0,500}?(?:overlay|modal|popup)/i,
      /createElement\s*\(\s*['"]div['"][\s\S]{0,200}?style[\s\S]{0,200}?(?:fixed|absolute)/i,
      /\.className\s*=[\s\S]{0,200}?(?:overlay|modal|popup)/i,
      /classList\.add[\s\S]{0,100}?(?:overlay|show|active)/i
    ]

    const overlayJsMatches = overlayPatterns.filter(p => p.test(combinedScripts))
    if (overlayJsMatches.length > 0) {
      score += Math.min(0.15, overlayJsMatches.length * 0.05)
      reasons.push('Script dynamically creates overlay/popup content')
    }

    // 6. Detect credential storage patterns (caching passwords)
    const credentialCachePatterns = [
      /localStorage\.setItem[\s\S]{0,200}?(?:pass|pwd|credential|token)/i,
      /sessionStorage\.setItem[\s\S]{0,200}?(?:pass|pwd|credential|token)/i,
      /\.cookie\s*=[^;]{0,200}?(?:pass|pwd|token|session|auth)/i,
      /indexedDB[\s\S]{0,500}?(?:pass|pwd|credential)/i
    ]

    if (credentialCachePatterns.some(p => p.test(combinedScripts))) {
      score += 0.15
      reasons.push('Script stores credentials in browser storage - credential caching')
    }

    // 7. Detect iframe communication patterns (cross-origin data exfiltration)
    const iframeCommPatterns = [
      /postMessage[\s\S]{0,500}?(?:pass|pwd|credential|token)/i,
      /contentWindow[\s\S]{0,200}?\.postMessage/i,
      /parent\.postMessage/i
    ]

    if (iframeCommPatterns.some(p => p.test(combinedScripts))) {
      score += 0.15
      reasons.push('Cross-origin messaging detected - possible iframe-based data exfiltration')
      details.iframeCommunication = true
    }

    // 8. Detect inline event handlers on password fields
    const inlineHandlerPatterns = /<input[^>]*?(?:onblur|onfocus|onkeyup|onkeydown|oninput|onchange)\s*=[^>]*>/gi
    const inlineHandlers = html.match(inlineHandlerPatterns)
    if (inlineHandlers && inlineHandlers.length > 0) {
      score += Math.min(0.1, inlineHandlers.length * 0.03)
      reasons.push(`Inline event handlers on form fields (${inlineHandlers.length})`)
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'SCRIPT TIME-SERIES ANALYSIS: JavaScript exhibits temporal patterns consistent with phishing kits. Delayed execution, form manipulation, and data exfiltration patterns detected.'
      : score > 0.2
        ? 'Some suspicious script timing patterns detected. JavaScript behavior has minor anomalies.'
        : 'Script timing and behavior patterns appear normal.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
