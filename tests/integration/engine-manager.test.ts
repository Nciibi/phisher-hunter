import { describe, it, expect, beforeEach } from 'vitest'
import { EngineManager } from '../../src/background/engines'
import type { EngineContext } from '../../src/shared/types/engines'

describe('EngineManager Integration', () => {
  let manager: EngineManager

  beforeEach(() => {
    manager = new EngineManager()
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

  it('creates all 9 engines', () => {
    const engines = manager.getAllEngines()
    expect(engines).toHaveLength(9)
  })

  it('analyzes a safe URL with all engines', async () => {
    const context = createContext('https://www.google.com')
    const results = await manager.analyzeAll(context)
    expect(results).toHaveLength(9)
    results.forEach(result => {
      expect(result.engineId).toBeTruthy()
      expect(typeof result.score).toBe('number')
      expect(typeof result.confidence).toBe('number')
      expect(Array.isArray(result.reasons)).toBe(true)
      expect(typeof result.recommendation).toBe('string')
    })
  })

  it('analyzes a suspicious URL with higher scores', async () => {
    const context = createContext('https://secure-paypal-login.xyz')
    const results = await manager.analyzeAll(context)
    const highScoring = results.filter(r => r.score > 0.3)
    expect(highScoring.length).toBeGreaterThan(0)
  })

  it('handles engine enabling/disabling', () => {
    expect(manager.setEngineEnabled('url-reputation', false)).toBe(true)
    const engine = manager.getEngine('url-reputation')
    expect(engine?.enabled).toBe(false)
    expect(manager.setEngineEnabled('nonexistent', false)).toBe(false)
  })

  it('provides engine status', () => {
    const status = manager.getEngineStatus()
    expect(status).toHaveLength(9)
    status.forEach(s => {
      expect(s.id).toBeTruthy()
      expect(s.name).toBeTruthy()
      expect(typeof s.enabled).toBe('boolean')
      expect(typeof s.weight).toBe('number')
    })
  })

  it('analyzes with redirect chain', async () => {
    const context = createContext('https://final.com', {
      redirectChain: ['https://click.example.com', 'https://redirect.tracker.net', 'https://final.com']
    })
    const results = await manager.analyzeAll(context)
    const redirectionEngine = results.find(r => r.engineId === 'redirection-chain')
    expect(redirectionEngine).toBeDefined()
    expect(redirectionEngine!.score).toBeGreaterThan(0)
  })

  it('analyzes with forms', async () => {
    const context = createContext('https://login.example.com', {
      forms: [{
        action: 'https://evil-collector.com/harvest.php',
        method: 'post',
        fields: [
          { type: 'email', name: 'email', id: 'email', placeholder: 'Email', isPassword: false, isHidden: false },
          { type: 'password', name: 'password', id: 'pass', placeholder: 'Password', isPassword: true, isHidden: false },
          { type: 'hidden', name: 'token', id: 'token', placeholder: '', isPassword: false, isHidden: true }
        ],
        hasPassword: true,
        hasSubmit: true,
        actionDomain: 'evil-collector.com',
        isExternal: true
      }]
    })
    const results = await manager.analyzeAll(context)
    const formEngines = results.filter(r =>
      ['form-destination', 'credential-harvesting', 'password-field'].includes(r.engineId)
    )
    formEngines.forEach(e => {
      expect(e.score).toBeGreaterThan(0)
    })
  })

  it('handles empty context gracefully', async () => {
    const context = createContext('https://example.com', {
      html: '',
      forms: [],
      scripts: [],
      links: [],
      iframes: []
    })
    const results = await manager.analyzeAll(context)
    expect(results).toHaveLength(9)
    results.forEach(r => {
      expect(r.error).toBeUndefined()
    })
  })

  it('detects homograph attack via all engines', async () => {
    const cyrillicE = '\u0435' // Cyrillic 'е' that looks like 'e'
    const homographDomain = `${cyrillicE}xample.com`
    const context = createContext(`https://${homographDomain}`, {
      hostname: homographDomain,
      domain: homographDomain
    })
    const results = await manager.analyzeAll(context)
    const homographResult = results.find(r => r.engineId === 'visual-fingerprint')
    expect(homographResult).toBeDefined()
    expect(homographResult!.score).toBeGreaterThan(0)
  })
})
