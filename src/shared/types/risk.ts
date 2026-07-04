import type { RiskLevel } from './analysis'

export interface RiskAssessment {
  overallRisk: RiskLevel
  overallScore: number
  confidence: number
  factors: RiskFactor[]
  summary: string
  timestamp: number
}

export interface RiskFactor {
  name: string
  description: string
  score: number
  weight: number
  contribution: number
  risk: RiskLevel
  evidence: string[]
}

export interface RiskWeights {
  credentialCanary: number
  visualFingerprint: number
  languageMatrix: number
  urlEntropy: number
  temporalClustering: number
  cssDeception: number
  scriptTimeseries: number
  certificateAnomaly: number
  interactiveHoneypot: number
}

export const DEFAULT_RISK_WEIGHTS: RiskWeights = {
  credentialCanary: 0.18,
  visualFingerprint: 0.15,
  languageMatrix: 0.13,
  urlEntropy: 0.12,
  temporalClustering: 0.12,
  cssDeception: 0.10,
  scriptTimeseries: 0.10,
  certificateAnomaly: 0.09,
  interactiveHoneypot: 0.07
}

export const RISK_SEVERITY_ORDER: RiskLevel[] = [
  'safe',
  'low',
  'medium',
  'high',
  'critical'
]

export function calculateContribution(
  score: number,
  weight: number
): number {
  return score * weight
}

export function getSeverityWeight(level: RiskLevel): number {
  const weights: Record<RiskLevel, number> = {
    safe: 0,
    low: 0.25,
    medium: 0.5,
    high: 0.75,
    critical: 1
  }
  return weights[level]
}
