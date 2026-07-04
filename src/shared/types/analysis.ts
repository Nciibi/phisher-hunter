export interface AnalysisResult {
  url: string
  domain: string
  timestamp: number
  risk: RiskLevel
  riskScore: number
  confidence: number
  engines: EngineResult[]
  reasons: string[]
  recommendations: string[]
  certificateInfo?: CertificateInfo
  domainAge?: DomainAgeInfo
  redirectionChain?: string[]
  isWhitelisted: boolean
  isBlacklisted: boolean
}

export interface EngineResult {
  engineId: string
  engineName: string
  score: number
  confidence: number
  risk: RiskLevel
  reasons: string[]
  recommendation: string
  details?: Record<string, unknown>
  duration: number
  error?: string
}

export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical'

export const RISK_LEVELS: Record<RiskLevel, number> = {
  safe: 0,
  low: 0.25,
  medium: 0.5,
  high: 0.75,
  critical: 1
}

export const RISK_THRESHOLDS = {
  safe: 0.15,
  low: 0.35,
  medium: 0.55,
  high: 0.75,
  critical: 1
} as const

export function getRiskLevel(score: number): RiskLevel {
  if (score <= RISK_THRESHOLDS.safe) return 'safe'
  if (score <= RISK_THRESHOLDS.low) return 'low'
  if (score <= RISK_THRESHOLDS.medium) return 'medium'
  if (score <= RISK_THRESHOLDS.high) return 'high'
  return 'critical'
}

export function getRiskColor(level: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    safe: '#34a853',
    low: '#8ab4f8',
    medium: '#fbbc04',
    high: '#ff6d01',
    critical: '#ea4335'
  }
  return colors[level]
}

export function getRiskLabel(level: RiskLevel): string {
  const labels: Record<RiskLevel, string> = {
    safe: 'Safe',
    low: 'Low Risk',
    medium: 'Medium Risk',
    high: 'High Risk',
    critical: 'Critical Threat'
  }
  return labels[level]
}

export interface CertificateInfo {
  issuer: string
  subject: string
  validFrom: number
  validTo: number
  isSelfSigned: boolean
  isExpired: boolean
  isValid: boolean
  fingerprint?: string
}

export interface DomainAgeInfo {
  created: number
  daysSinceCreation: number
  isNew: boolean
  registrar?: string
  daysUntilExpiry?: number
}
