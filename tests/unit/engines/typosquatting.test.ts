import { describe, it, expect, beforeEach } from 'vitest'
import { TyposquattingEngine } from '../../../src/background/engines/typosquatting'
import type { EngineContext } from '../../../src/shared/types/engines'

describe('TyposquattingEngine', () => {
  let engine: TyposquattingEngine

  beforeEach(() => {
    engine = new TyposquattingEngine()
  })

  const createContext = (hostname: string): EngineContext => ({
    url: `https://${hostname}`,
    domain: hostname,
    hostname,
    protocol: 'https:',
    port: '',
    path: '/',
    query: '',
    fragment: '',
    tld: '.' + hostname.split('.').pop(),
    subdomains: hostname.split('.').length > 2 ? hostname.split('.').slice(0, -2) : []
  })

  it('detects google typo', async () => {
    const result = await engine.analyze(createContext('go0gle.com'))
    expect(result.score).toBeGreaterThan(0.3)
    expect(result.reasons.length).toBeGreaterThan(0)
  })

  it('detects TLD substitution', async () => {
    const result = await engine.analyze(createContext('google.xyz'))
    expect(result.score).toBeGreaterThan(0.3)
  })

  it('does not flag legitimate domain', async () => {
    const result = await engine.analyze(createContext('my-own-website.com'))
    expect(result.score).toBe(0)
  })

  it('detects subdomain trick with brand', async () => {
    const result = await engine.analyze(createContext('google.com.evil.com'))
    expect(result.score).toBeGreaterThan(0.3)
  })

  it('detects paypal typosquatting', async () => {
    const result = await engine.analyze(createContext('paypallogin.com'))
    expect(result.score).toBeGreaterThan(0.3)
  })
})
