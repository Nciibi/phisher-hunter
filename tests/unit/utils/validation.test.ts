import { describe, it, expect } from 'vitest'
import { sanitizeHtml, sanitizeUrl, validateDomain, isProbablyMaliciousScript, truncateString } from '../../../src/shared/utils/validation'

describe('Validation Utils', () => {
  describe('sanitizeHtml', () => {
    it('escapes HTML entities', () => {
      expect(sanitizeHtml('<script>alert("xss")</script>'))
        .toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
    })
    it('handles safe strings', () => {
      expect(sanitizeHtml('hello world')).toBe('hello world')
    })
  })

  describe('sanitizeUrl', () => {
    it('allows https URLs', () => {
      expect(sanitizeUrl('https://example.com')).toBe('https://example.com')
    })
    it('rejects javascript URLs', () => {
      expect(sanitizeUrl('javascript:alert(1)')).toBe('')
    })
  })

  describe('validateDomain', () => {
    it('validates correct domains', () => {
      expect(validateDomain('example.com')).toBe(true)
      expect(validateDomain('sub.example.com')).toBe(true)
    })
    it('rejects invalid domains', () => {
      expect(validateDomain('')).toBe(false)
      expect(validateDomain('not a domain')).toBe(false)
    })
  })

  describe('isProbablyMaliciousScript', () => {
    it('detects eval usage', () => {
      expect(isProbablyMaliciousScript('eval("some code")')).toBe(true)
    })
    it('detects base64 decoding', () => {
      expect(isProbablyMaliciousScript('atob("base64string")')).toBe(true)
    })
    it('allows safe scripts', () => {
      expect(isProbablyMaliciousScript('console.log("hello")')).toBe(false)
    })
  })

  describe('truncateString', () => {
    it('truncates long strings', () => {
      const result = truncateString('hello world this is long', 10)
      expect(result.length).toBeLessThanOrEqual(13)
      expect(result).toBe('hello w...')
    })
    it('keeps short strings', () => {
      expect(truncateString('hello', 10)).toBe('hello')
    })
  })
})
