import { describe, it, expect } from 'vitest'
import {
  getDomain,
  getHostname,
  getTLD,
  getSubdomains,
  isSuspiciousTLD,
  isHighRiskTLD,
  hasIpAddress,
  countDots,
  countHyphens,
  countDigits,
  getRegistrableDomain,
  normalizeUrl,
  isValidUrl,
  getBrandForDomain
} from '../../../src/shared/utils/url'

describe('URL Utils', () => {
  describe('getDomain', () => {
    it('returns hostname from full URL', () => {
      expect(getDomain('https://www.example.com/path')).toBe('www.example.com')
    })
    it('handles URLs without protocol', () => {
      expect(getDomain('example.com')).toBe('example.com')
    })
    it('handles empty input', () => {
      expect(getDomain('')).toBe('')
    })
  })

  describe('getHostname', () => {
    it('extracts hostname correctly', () => {
      expect(getHostname('https://sub.example.com:8080/path')).toBe('sub.example.com')
    })
  })

  describe('getTLD', () => {
    it('extracts simple TLD', () => {
      expect(getTLD('example.com')).toBe('.com')
    })
    it('extracts known public suffix', () => {
      expect(getTLD('example.co.uk')).toBe('.co.uk')
    })
    it('handles subdomains', () => {
      expect(getTLD('sub.example.org')).toBe('.org')
    })
  })

  describe('getSubdomains', () => {
    it('returns subdomains', () => {
      expect(getSubdomains('sub.example.com')).toEqual(['sub'])
    })
    it('returns multiple subdomains', () => {
      expect(getSubdomains('a.b.example.com')).toEqual(['a', 'b'])
    })
    it('returns empty for no subdomains', () => {
      expect(getSubdomains('example.com')).toEqual([])
    })
  })

  describe('isSuspiciousTLD', () => {
    it('detects suspicious TLDs', () => {
      expect(isSuspiciousTLD('.xyz')).toBe(true)
      expect(isSuspiciousTLD('.top')).toBe(true)
      expect(isSuspiciousTLD('.com')).toBe(false)
    })
    it('is case insensitive', () => {
      expect(isSuspiciousTLD('.XYZ')).toBe(true)
    })
  })

  describe('isHighRiskTLD', () => {
    it('detects high risk TLDs', () => {
      expect(isHighRiskTLD('.tk')).toBe(true)
      expect(isHighRiskTLD('.ml')).toBe(true)
      expect(isHighRiskTLD('.com')).toBe(false)
    })
  })

  describe('hasIpAddress', () => {
    it('detects IPv4', () => {
      expect(hasIpAddress('192.168.1.1')).toBe(true)
    })
    it('rejects domain names', () => {
      expect(hasIpAddress('example.com')).toBe(false)
    })
    it('detects IPv6', () => {
      expect(hasIpAddress('2001:db8::1')).toBe(true)
    })
  })

  describe('countDots', () => {
    it('counts dots in URL', () => {
      expect(countDots('https://sub.example.com')).toBe(2)
    })
    it('returns 0 for no dots', () => {
      expect(countDots('localhost')).toBe(0)
    })
  })

  describe('countHyphens', () => {
    it('counts hyphens in hostname', () => {
      expect(countHyphens('my-example-site.com')).toBe(2)
    })
  })

  describe('countDigits', () => {
    it('counts digits in hostname', () => {
      expect(countDigits('test123example456.com')).toBe(6)
    })
  })

  describe('getRegistrableDomain', () => {
    it('returns registrable domain', () => {
      expect(getRegistrableDomain('sub.example.co.uk')).toBe('example.co.uk')
    })
  })

  describe('normalizeUrl', () => {
    it('normalizes URL', () => {
      expect(normalizeUrl('https://example.com/path/')).toBe('https://example.com/path')
    })
  })

  describe('isValidUrl', () => {
    it('validates correct URLs', () => {
      expect(isValidUrl('https://example.com')).toBe(true)
    })
    it('rejects invalid URLs', () => {
      expect(isValidUrl('not a url')).toBe(false)
    })
  })

  describe('getBrandForDomain', () => {
    it('matches known brand', () => {
      expect(getBrandForDomain('google.com')).toBe('google')
    })
    it('matches subdomain of brand', () => {
      expect(getBrandForDomain('mail.google.com')).toBe('google')
    })
    it('returns null for unknown', () => {
      expect(getBrandForDomain('unknown-site.com')).toBeNull()
    })
  })
})
