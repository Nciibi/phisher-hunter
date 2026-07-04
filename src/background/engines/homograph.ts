import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { detectHomographInString } from '../../shared/utils/domain'
import { HOMOGLITCH_CHARACTERS } from '../../shared/constants'

export class HomographEngine extends BaseEngine {
  id = 'homograph'
  name = 'Homograph Attack Detection'
  description = 'Detects homograph attacks using visually similar characters'
  version = '1.0.0'
  weight = 10

  private readonly confusableMap: Map<string, string> = new Map([
    ['\u0430', 'a'], ['\u0435', 'e'], ['\u043E', 'o'],
    ['\u0440', 'p'], ['\u0441', 'c'], ['\u0443', 'y'],
    ['\u0456', 'i'], ['\u0454', 'e'], ['\u04BB', 'h'],
    ['\u04E9', 'o'], ['\u0501', 'd'], ['\u0432', 'b'],
    ['\u043A', 'k'], ['\u043C', 'm'], ['\u04AF', 'y'],
    ['\u00E0', 'a'], ['\u00E1', 'a'], ['\u00E2', 'a'],
    ['\u00E3', 'a'], ['\u00E4', 'a'], ['\u00E5', 'a'],
    ['\u00E8', 'e'], ['\u00E9', 'e'], ['\u00EA', 'e'],
    ['\u00EB', 'e'], ['\u00EC', 'i'], ['\u00ED', 'i'],
    ['\u00EE', 'i'], ['\u00EF', 'i'], ['\u00F2', 'o'],
    ['\u00F3', 'o'], ['\u00F4', 'o'], ['\u00F5', 'o'],
    ['\u00F6', 'o'], ['\u00F9', 'u'], ['\u00FA', 'u'],
    ['\u00FB', 'u'], ['\u00FC', 'u'], ['\u0101', 'a'],
    ['\u0113', 'e'], ['\u012B', 'i'], ['\u014D', 'o'],
    ['\u016B', 'u'], ['\u00FD', 'y'], ['\u00FF', 'y']
  ])

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.9

    const hostname = context.hostname.toLowerCase()
    const fullUrl = context.url

    const homographChars = this.findHomographCharacters(hostname)
    details.homographChars = homographChars

    if (homographChars.length > 0) {
      const decoded = this.decodeHomographString(hostname)
      details.decodedString = decoded

      score += Math.min(0.8, homographChars.length * 0.15)

      const decodedNormalized = this.normalizeForComparison(decoded)
      if (decodedNormalized !== hostname) {
        reasons.push(
          `Homograph attack detected: "${hostname}" contains visually deceptive characters that render as "${decoded}"`
        )
      }

      const homographDetails = homographChars.map(c => {
        const codePoint = c.codePointAt(0)?.toString(16).toUpperCase()
        const replacement = this.confusableMap.get(c)
        return {
          char: c,
          unicode: `U+${codePoint}`,
          resembles: replacement || '?'
        }
      })
      details.chars = homographDetails

      const encodedParams = this.findEncodedCharacters(fullUrl)
      if (encodedParams.length > 0) {
        score += 0.2
        reasons.push(
          `URL contains ${encodedParams.length} percent-encoded homograph characters`
        )
        details.encodedChars = encodedParams
      }

      if (homographChars.length >= 3) {
        reasons.push(
          `Multiple (${homographChars.length}) homograph characters detected in domain`
        )
      }

      reasons.push(
        'Homograph attacks trick users by substituting visually identical Unicode characters'
      )
    } else {
      reasons.push('No homograph characters detected')
    }

    score = Math.min(1, score)

    const recommendation = score > 0.4
      ? 'This domain uses deceptive Unicode characters to mimic a legitimate URL. Do not trust this site.'
      : 'No homograph-based deception detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private findHomographCharacters(input: string): string[] {
    const found: string[] = []
    for (const char of input) {
      if (HOMOGLITCH_CHARACTERS.has(char)) {
        found.push(char)
      }
    }
    return found
  }

  private decodeHomographString(input: string): string {
    let result = ''
    for (const char of input) {
      const replacement = this.confusableMap.get(char)
      result += replacement || char
    }
    return result
  }

  private normalizeForComparison(input: string): string {
    return input.normalize('NFKC').toLowerCase()
  }

  private findEncodedCharacters(url: string): string[] {
    const encoded: string[] = []
    const matches = url.match(/%[0-9a-fA-F]{2}/g) || []
    for (const match of matches) {
      const decoded = decodeURIComponent(match)
      if (HOMOGLITCH_CHARACTERS.has(decoded)) {
        encoded.push(match)
      }
    }
    return encoded
  }
}
