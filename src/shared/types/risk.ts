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
  urlReputation: number
  domainAge: number
  typosquatting: number
  homograph: number
  unicodeAttack: number
  suspiciousTld: number
  certificate: number
  phishingFeeds: number
  javascriptHeuristics: number
  credentialHarvesting: number
  hiddenIframe: number
  passwordField: number
  brandImpersonation: number
  htmlStructure: number
  formDestination: number
  redirectionChain: number
  screenshotSimilarity: number
}

export const DEFAULT_RISK_WEIGHTS: RiskWeights = {
  urlReputation: 0.15,
  domainAge: 0.08,
  typosquatting: 0.12,
  homograph: 0.10,
  unicodeAttack: 0.10,
  suspiciousTld: 0.05,
  certificate: 0.10,
  phishingFeeds: 0.15,
  javascriptHeuristics: 0.08,
  credentialHarvesting: 0.12,
  hiddenIframe: 0.05,
  passwordField: 0.05,
  brandImpersonation: 0.12,
  htmlStructure: 0.08,
  formDestination: 0.10,
  redirectionChain: 0.08,
  screenshotSimilarity: 0.10
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
