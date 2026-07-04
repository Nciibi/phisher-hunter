import { describe, it, expect } from 'vitest'
import {
  detectTyposquatting,
  detectHomographAttack,
  levenshteinDistance,
  computeStringSimilarity,
  extractBrandKeywords
} from '../../../src/shared/utils/domain'

describe('Domain Utils', () => {
  describe('levenshteinDistance', () => {
    it('returns 0 for identical strings', () => {
      expect(levenshteinDistance('test', 'test')).toBe(0)
    })
    it('detects single character difference', () => {
      expect(levenshteinDistance('test', 'tent')).toBe(1)
    })
    it('handles empty strings', () => {
      expect(levenshteinDistance('', 'test')).toBe(4)
    })
    it('detects insertions', () => {
      expect(levenshteinDistance('test', 'tests')).toBe(1)
    })
    it('detects deletions', () => {
      expect(levenshteinDistance('tests', 'test')).toBe(1)
    })
  })

  describe('computeStringSimilarity', () => {
    it('returns 1 for identical strings', () => {
      expect(computeStringSimilarity('test', 'test')).toBe(1)
    })
    it('returns 0 for completely different strings', () => {
      expect(computeStringSimilarity('abc', 'xyz')).toBe(0)
    })
    it('handles empty strings', () => {
      expect(computeStringSimilarity('', '')).toBe(1)
    })
  })

  describe('detectHomographAttack', () => {
    it('detects Cyrillic homograph', () => {
      const cyrillicE = '\u0435' // Cyrillic 'е'
      expect(detectHomographAttack(cyrillicE + 'xample', 'example')).toBe(true)
    })
    it('returns false for identical strings', () => {
      expect(detectHomographAttack('example', 'example')).toBe(false)
    })
    it('returns false for very different strings', () => {
      expect(detectHomographAttack('nothing', 'example')).toBe(false)
    })
  })

  describe('detectTyposquatting', () => {
    it('detects TLD substitution for google', () => {
      const result = detectTyposquatting('google.xyz')
      expect(result.isSuspicious).toBe(true)
      expect(result.type).toBe('tld_substitution')
    })

    it('detects typosquatting for googgle', () => {
      const result = detectTyposquatting('googgle.com')
      expect(result.isSuspicious).toBe(true)
      expect(result.type).toBe('typo')
    })

    it('returns safe for legitimate domain', () => {
      const result = detectTyposquatting('legitimate-site.com')
      expect(result.isSuspicious).toBe(false)
    })

    it('detects subdomain trick', () => {
      const result = detectTyposquatting('google.malicious-site.xyz')
      expect(result.isSuspicious).toBe(true)
    })

    it('detects extra domain embedding', () => {
      const result = detectTyposquatting('paypalsecure-login.com')
      expect(result.isSuspicious).toBe(true)
    })
  })

  describe('extractBrandKeywords', () => {
    it('extracts brand names from text', () => {
      const result = extractBrandKeywords('Please login to your google account')
      expect(result).toContain('google')
    })
    it('returns empty for no brand matches', () => {
      const result = extractBrandKeywords('Some random text without brands')
      expect(result).toEqual([])
    })
  })
})
