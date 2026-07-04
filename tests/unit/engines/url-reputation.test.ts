import { describe, it, expect, beforeEach } from 'vitest'
import { UrlReputationEngine } from '../../../src/background/engines/url-reputation'
import type { EngineContext } from '../../../src/shared/types/engines'

describe('UrlReputationEngine', () => {
  let engine: UrlReputationEngine

  beforeEach(() => {
    engine = new UrlReputationEngine()
  })

  const createContext = (url: string, overrides?: Partial<EngineContext>): EngineContext => ({
    url,
    domain: new URL(url).hostname,
    hostname: new URL(url).hostname,
    protocol: new URL(url).protocol,
    port: new URL(url).port,
    path: new URL(url).pathname,
    query: new URL(url).search,
    fragment: new URL(url).hash,
    tld: '.' + new URL(url).hostname.split('.').pop(),
    subdomains: [],
    ...overrides
  })

  it('detects IP address URLs', async () => {
    const context = createContext('http://192.168.1.1/login')
    const result = await engine.analyze(context)
    expect(result.score).toBeGreaterThan(0)
    expect(result.reasons.some(r => r.includes('IP address'))).toBe(true)
  })

  it('detects excessive dots', async () => {
    const context = createContext('http://a.b.c.d.e.f.example.com')
    const result = await engine.analyze(context)
    expect(result.score).toBeGreaterThan(0)
  })

  it('detects @ symbol in URL', async () => {
    const context = createContext('http://real-site.com@evil-site.com/login')
    const result = await engine.analyze(context)
    expect(result.score).toBeGreaterThan(0.4)
    expect(result.reasons.some(r => r.includes('@'))).toBe(true)
  })

  it('gives safe score for normal URL', async () => {
    const context = createContext('https://www.google.com/search?q=test')
    const result = await engine.analyze(context)
    expect(result.score).toBeLessThan(0.3)
  })

  it('detects non-standard port', async () => {
    const context = createContext('http://example.com:8080')
    const result = await engine.analyze(context)
    expect(result.score).toBeGreaterThan(0)
  })

  it('detects excessive hyphens', async () => {
    const context = createContext('http://this-is-a-very-suspicious-domain-name.com')
    const result = await engine.analyze(context)
    expect(result.score).toBeGreaterThan(0)
  })
})
