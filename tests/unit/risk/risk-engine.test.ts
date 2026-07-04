import { describe, it, expect, beforeEach } from 'vitest'
import { RiskEngine } from '../../../src/background/risk/risk-engine'
import type { EngineResult } from '../../../src/shared/types/engines'

describe('RiskEngine', () => {
  let riskEngine: RiskEngine

  beforeEach(() => {
    riskEngine = new RiskEngine()
  })

  const makeEngineResult = (overrides?: Partial<EngineResult>): EngineResult => ({
    engineId: 'test-engine',
    engineName: 'Test Engine',
    score: 0,
    confidence: 0.8,
    risk: 'safe',
    reasons: [],
    recommendation: '',
    duration: 10,
    ...overrides
  })

  it('marks blacklisted domains as critical', () => {
    const result = riskEngine.calculateRisk(
      'https://evil.com',
      'evil.com',
      [],
      { isWhitelisted: false, isBlacklisted: true }
    )
    expect(result.risk).toBe('critical')
    expect(result.riskScore).toBe(1)
    expect(result.confidence).toBe(1)
  })

  it('marks whitelisted domains as safe', () => {
    const result = riskEngine.calculateRisk(
      'https://trusted.com',
      'trusted.com',
      [],
      { isWhitelisted: true, isBlacklisted: false }
    )
    expect(result.risk).toBe('safe')
    expect(result.riskScore).toBe(0)
  })

  it('returns safe for no engine results', () => {
    const result = riskEngine.calculateRisk(
      'https://example.com',
      'example.com',
      [],
      { isWhitelisted: false, isBlacklisted: false }
    )
    expect(result.risk).toBe('safe')
    expect(result.riskScore).toBe(0)
  })

  it('correctly weights high-scoring engines', () => {
    const results = [
      makeEngineResult({
        engineId: 'credential-canary',
        score: 1,
        confidence: 0.9,
        risk: 'critical'
      }),
      makeEngineResult({
        engineId: 'visual-fingerprint',
        score: 0.5,
        confidence: 0.8,
        risk: 'high'
      })
    ]

    const result = riskEngine.calculateRisk(
      'https://phishing-site.com',
      'phishing-site.com',
      results,
      { isWhitelisted: false, isBlacklisted: false }
    )

    expect(result.riskScore).toBeGreaterThan(0.5)
    expect(result.confidence).toBeGreaterThan(0.5)
  })

  it('provides recommendations for high risk', () => {
    const results = [
      makeEngineResult({
        engineId: 'credential-canary',
        score: 1,
        confidence: 0.95,
        risk: 'critical',
        reasons: ['Credential canary triggered']
      })
    ]

    const result = riskEngine.calculateRisk(
      'https://phishing-site.com',
      'phishing-site.com',
      results,
      { isWhitelisted: false, isBlacklisted: false }
    )

    expect(result.recommendations.length).toBeGreaterThan(0)
    expect(result.reasons.length).toBeGreaterThan(0)
  })

  it('handles mixed engine results', () => {
    const results = [
      makeEngineResult({ engineId: 'domain-age', score: 0.8, confidence: 0.7, risk: 'high' }),
      makeEngineResult({ engineId: 'suspicious-tld', score: 0, confidence: 0.6, risk: 'safe' }),
      makeEngineResult({ engineId: 'certificate', score: 0.9, confidence: 0.85, risk: 'critical' })
    ]

    const result = riskEngine.calculateRisk(
      'https://suspicious-site.xyz',
      'suspicious-site.xyz',
      results,
      { isWhitelisted: false, isBlacklisted: false }
    )

    expect(result.risk).not.toBe('safe')
    expect(result.riskScore).toBeGreaterThan(0.3)
  })

  describe('getDetailedAssessment', () => {
    it('returns proper assessment structure', () => {
      const results = [
        makeEngineResult({
          engineId: 'phishing-feeds',
          score: 0.8,
          confidence: 0.9,
          risk: 'high',
          reasons: ['Found in phishing database']
        })
      ]

      const assessment = riskEngine.getDetailedAssessment(results)
      expect(assessment.overallRisk).toBeDefined()
      expect(assessment.overallScore).toBeGreaterThan(0)
      expect(assessment.factors.length).toBeGreaterThan(0)
      expect(assessment.summary).toBeTruthy()
    })
  })
})
