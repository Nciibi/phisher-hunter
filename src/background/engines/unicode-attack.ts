import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

export class UnicodeAttackEngine extends BaseEngine {
  id = 'unicode-attack'
  name = 'Unicode Attack Detection'
  description = 'Detects Unicode-based attacks like right-to-left override and zero-width characters'
  version = '1.0.0'
  weight = 10

  private readonly DANGEROUS_CHARS = new Set([
    '\u200B', '\u200C', '\u200D', '\uFEFF',
    '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
    '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
    '\u2066', '\u2067', '\u2068', '\u2069',
    '\u00AD', '\u061C',
    '\u034F', '\u180B', '\u180C', '\u180D', '\u180E',
    '\u200E', '\u200F',
    '\u2060', '\u2066', '\u2067', '\u2068', '\u2069',
  ])

  private readonly rtlOverride = '\u202E'
  private readonly popDirectional = '\u202C'

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.95

    const hostname = context.hostname
    const fullUrl = context.url

    const dangerousChars = this.findDangerousCharacters(fullUrl)
    details.dangerousChars = dangerousChars

    const hasRtlOverride = fullUrl.includes(this.rtlOverride)
    if (hasRtlOverride) {
      score += 0.9
      reasons.push(
        'CRITICAL: Right-to-Left override character detected (U+202E). This is used to spoof domain names.'
      )
      const rtlDecoded = this.decodeRtlString(fullUrl)
      details.rtlDecoded = rtlDecoded
      if (rtlDecoded) {
        reasons.push(`When decoded for RTL override, the string reads as: "${rtlDecoded}"`)
      }
    }

    if (dangerousChars.length > 0) {
      const nonRtlCount = dangerousChars.filter(c => c !== this.rtlOverride && c !== this.popDirectional).length
      score += Math.min(0.3, nonRtlCount * 0.05)

      for (const char of dangerousChars) {
        const codePoint = char.codePointAt(0)?.toString(16).toUpperCase()
        const description = this.getCharDescription(char)
        reasons.push(
          `Suspicious Unicode character U+${codePoint} detected: ${description}`
        )
      }
    }

    const zeroWidthCount = this.countZeroWidthCharacters(fullUrl)
    if (zeroWidthCount > 0) {
      score += Math.min(0.4, zeroWidthCount * 0.1)
      reasons.push(
        `${zeroWidthCount} zero-width character${zeroWidthCount > 1 ? 's' : ''} detected. These can be used to hide text.`
      )
      details.zeroWidthCount = zeroWidthCount
    }

    const normalizedNfkc = fullUrl.normalize('NFKC')
    if (normalizedNfkc !== fullUrl) {
      score += 0.15
      reasons.push('URL contains Unicode normalization differences, suggesting obfuscation')
      details.normalizedForm = normalizedNfkc
    }

    const bidirectionalChars = this.findBidirectionalCharacters(fullUrl)
    if (bidirectionalChars.length > 0) {
      score += Math.min(0.3, bidirectionalChars.length * 0.08)
      reasons.push(
        `${bidirectionalChars.length} bidirectional override character${bidirectionalChars.length > 1 ? 's' : ''} detected`
      )
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'This URL uses dangerous Unicode characters designed to trick users. Do not trust this site.'
      : 'No suspicious Unicode manipulation detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private findDangerousCharacters(input: string): string[] {
    const found: string[] = []
    for (const char of input) {
      if (this.DANGEROUS_CHARS.has(char)) {
        found.push(char)
      }
    }
    return found
  }

  private countZeroWidthCharacters(input: string): number {
    let count = 0
    for (const char of input) {
      const codePoint = char.codePointAt(0) || 0
      if (codePoint === 0x200B || codePoint === 0x200C ||
          codePoint === 0x200D || codePoint === 0xFEFF ||
          codePoint === 0x2060 || codePoint === 0x180E) {
        count++
      }
    }
    return count
  }

  private findBidirectionalCharacters(input: string): string[] {
    const bidirectional: string[] = []
    for (const char of input) {
      const codePoint = char.codePointAt(0) || 0
      if ((codePoint >= 0x202A && codePoint <= 0x202E) ||
          (codePoint >= 0x2066 && codePoint <= 0x2069)) {
        bidirectional.push(char)
      }
    }
    return bidirectional
  }

  private getCharDescription(char: string): string {
    const desc: Record<string, string> = {
      '\u200B': 'Zero-width space',
      '\u200C': 'Zero-width non-joiner',
      '\u200D': 'Zero-width joiner',
      '\uFEFF': 'Byte order mark / zero-width no-break space',
      '\u202A': 'Left-to-right embedding',
      '\u202B': 'Right-to-left embedding',
      '\u202C': 'Pop directional formatting',
      '\u202D': 'Left-to-right override',
      '\u202E': 'Right-to-left override',
      '\u2060': 'Word joiner',
      '\u2061': 'Function application',
      '\u2062': 'Invisible times',
      '\u2063': 'Invisible separator',
      '\u2064': 'Invisible plus',
      '\u2066': 'Left-to-right isolate',
      '\u2067': 'Right-to-left isolate',
      '\u2068': 'First strong isolate',
      '\u2069': 'Pop directional isolate',
      '\u00AD': 'Soft hyphen',
      '\u061C': 'Arabic letter mark',
      '\u034F': 'Combining grapheme joiner',
      '\u180B': 'Mongolian free variation selector 1',
      '\u180C': 'Mongolian free variation selector 2',
      '\u180D': 'Mongolian free variation selector 3',
      '\u180E': 'Mongolian vowel separator',
      '\u200E': 'Left-to-right mark',
      '\u200F': 'Right-to-left mark'
    }
    return desc[char] || `Unicode U+${char.codePointAt(0)?.toString(16).toUpperCase()}`
  }

  private decodeRtlString(input: string): string | null {
    const rtlIdx = input.indexOf(this.rtlOverride)
    if (rtlIdx === -1) return null

    const before = input.slice(0, rtlIdx)
    const after = input.slice(rtlIdx + 1)

    const popIdx = after.indexOf(this.popDirectional)
    const rtlContent = popIdx === -1 ? after : after.slice(0, popIdx)

    const reversed = rtlContent.split('').reverse().join('')
    return before + reversed + (popIdx === -1 ? '' : after.slice(popIdx + 1))
  }
}
