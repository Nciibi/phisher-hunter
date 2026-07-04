import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { URL_ENTROPY_THRESHOLDS } from '../../shared/constants'

/**
 * URL ENTROPY ANALYSIS
 * 
 * Novel technique: Calculates Shannon entropy of each URL component.
 * Phishing URLs tend to have high-entropy (random-looking) subdomains,
 * paths, and query parameters compared to legitimate sites which use
 * meaningful, predictable URL structures.
 * 
 * Also computes:
 * - Character distribution analysis
 * - Base64-encoded segment detection
 * - Random string detection (consonant/vowel ratio, repeating chars)
 * - UUID/GUID pattern detection in paths
 */
export class UrlEntropyEngine extends BaseEngine {
  id = 'url-entropy'
  name = 'URL Entropy Analysis'
  description = 'Calculates Shannon entropy of URL components to detect randomized phishing URLs'
  version = '2.0.0'
  weight = 12

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.88

    const hostname = context.hostname
    const path = context.path
    const query = context.query
    const subdomains = context.subdomains

    // 1. Calculate entropy for each component
    const hostEntropy = this.shannonEntropy(hostname.replace(/\./g, ''))
    const pathEntropy = this.shannonEntropy(path.replace(/\//g, ''))
    const queryEntropy = query ? this.shannonEntropy(query.replace(/[?&=]/g, '')) : 0
    const subdomainEntropy = subdomains.length > 0
      ? this.shannonEntropy(subdomains.join(''))
      : 0

    details.entropyScores = {
      hostname: Math.round(hostEntropy * 100) / 100,
      path: Math.round(pathEntropy * 100) / 100,
      query: Math.round(queryEntropy * 100) / 100,
      subdomains: Math.round(subdomainEntropy * 100) / 100
    }

    // 2. Score based on component entropy
    if (subdomainEntropy > URL_ENTROPY_THRESHOLDS.SUBDOMAIN_HIGH && subdomains.length > 0) {
      score += 0.25
      reasons.push(
        `High-entropy subdomain (${subdomainEntropy.toFixed(1)} bits) - appears randomly generated`
      )
    }

    if (pathEntropy > URL_ENTROPY_THRESHOLDS.PATH_HIGH && path.length > 5) {
      score += 0.2
      reasons.push(
        `High-entropy path (${pathEntropy.toFixed(1)} bits) - appears randomly generated`
      )
    }

    if (queryEntropy > URL_ENTROPY_THRESHOLDS.QUERY_HIGH && query.length > 10) {
      score += 0.15
      reasons.push(
        `High-entropy query string (${queryEntropy.toFixed(1)} bits) - unusual for legitimate sites`
      )
    }

    // 3. Detect specific random patterns

    // Check for base64-encoded segments in path
    const pathSegments = path.split('/').filter(Boolean)
    const base64Segments = pathSegments.filter(s =>
      /^[A-Za-z0-9+/]{20,}={0,2}$/.test(s)
    )
    if (base64Segments.length > 0) {
      score += 0.2
      reasons.push(`Path contains ${base64Segments.length} base64-encoded segment(s)`)
      details.base64Segments = base64Segments
    }

    // Check for UUID/GUID patterns in path
    const uuidPattern = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
    const uuidMatches = path.match(uuidPattern)
    if (uuidMatches && uuidMatches.length > 0) {
      score += 0.1
      reasons.push(`Path contains ${uuidMatches.length} UUID(s) - unusual for login pages`)
    }

    // Check for hex-encoded segments
    const hexSegments = pathSegments.filter(s =>
      /^[0-9a-f]{16,}$/i.test(s)
    )
    if (hexSegments.length > 0) {
      score += 0.15
      reasons.push(`Path contains hex-encoded segment(s) - possible URL obfuscation`)
    }

    // 4. Analyze hostname character distribution
    const hostChars = hostname.replace(/\./g, '').split('')
    const digitRatio = hostChars.filter(c => /\d/.test(c)).length / Math.max(1, hostChars.length)
    const specialRatio = hostChars.filter(c => /[^a-zA-Z0-9]/.test(c)).length / Math.max(1, hostChars.length)

    if (digitRatio > 0.4) {
      score += 0.15
      reasons.push(`High digit ratio in domain (${Math.round(digitRatio * 100)}% digits)`)
    }

    if (specialRatio > 0.1) {
      score += 0.1
      reasons.push(`Unusual characters in domain (${Math.round(specialRatio * 100)}% special chars)`)
    }

    // 5. Random string detection using consonant/vowel ratio
    const hostClean = hostname.replace(/\./g, '')
    const consonantVowelRatio = this.consonantVowelRatio(hostClean)
    if (consonantVowelRatio > 3 || consonantVowelRatio < 0.3) {
      score += 0.1
      reasons.push('Abnormal consonant/vowel ratio suggests randomly generated domain')
    }

    // 6. Check for repetitive characters (sign of random generation)
    const repetitionScore = this.detectRepetitiveChars(hostClean)
    if (repetitionScore > 0.3) {
      score += 0.1
      reasons.push('Domain contains repetitive character patterns')
    }

    // 7. Analyze path depth vs entropy correlation
    const pathDepth = pathSegments.length
    if (pathDepth >= 4 && pathEntropy > 3.5) {
      score += 0.1
      reasons.push(`Deep path with high entropy (${pathDepth} segments, ${pathEntropy.toFixed(1)} bits)`)
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'URL structure analysis reveals statistically anomalous entropy patterns consistent with phishing infrastructure. The URL components appear randomly generated.'
      : score > 0.2
        ? 'URL entropy is slightly elevated. The URL structure has some unusual characteristics.'
        : 'URL entropy is within normal range for legitimate websites.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  /**
   * Shannon entropy calculation: -Σ(p(x) * log2(p(x)))
   * Measures the unpredictability of a string.
   * Higher values = more random = more suspicious for URLs.
   */
  private shannonEntropy(input: string): number {
    if (!input) return 0
    const len = input.length
    const freq: Record<string, number> = {}

    for (const char of input) {
      freq[char] = (freq[char] || 0) + 1
    }

    let entropy = 0
    for (const char in freq) {
      const p = freq[char] / len
      entropy -= p * Math.log2(p)
    }

    return entropy
  }

  private consonantVowelRatio(input: string): number {
    const vowels = 'aeiou'
    let vowelCount = 0
    let consonantCount = 0

    for (const char of input.toLowerCase()) {
      if (/[a-z]/.test(char)) {
        if (vowels.includes(char)) {
          vowelCount++
        } else {
          consonantCount++
        }
      }
    }

    if (vowelCount === 0) return Infinity
    return consonantCount / vowelCount
  }

  private detectRepetitiveChars(input: string): number {
    let maxRun = 1
    let currentRun = 1

    for (let i = 1; i < input.length; i++) {
      if (input[i] === input[i - 1]) {
        currentRun++
        maxRun = Math.max(maxRun, currentRun)
      } else {
        currentRun = 1
      }
    }

    return input.length > 0 ? maxRun / input.length : 0
  }
}
