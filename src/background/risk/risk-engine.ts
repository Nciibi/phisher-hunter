import type { EngineResult } from '../../shared/types/engines'
import type { AnalysisResult, RiskLevel } from '../../shared/types/analysis'
import { getRiskLevel, RISK_THRESHOLDS } from '../../shared/types/analysis'
import type { RiskAssessment, RiskFactor } from '../../shared/types/risk'

export class RiskEngine {
  private readonly MIN_CONFIDENCE_THRESHOLD = 0.1

  calculateRisk(
    url: string,
    domain: string,
    engineResults: EngineResult[],
    context: {
      isWhitelisted: boolean
      isBlacklisted: boolean
      certificateInfo?: AnalysisResult['certificateInfo']
      domainAge?: AnalysisResult['domainAgeInfo']
      redirectionChain?: string[]
    }
  ): AnalysisResult {
    const timestamp = Date.now()

    if (context.isBlacklisted) {
      return {
        url,
        domain,
        timestamp,
        risk: 'critical',
        riskScore: 1,
        confidence: 1,
        engines: engineResults,
        reasons: ['Domain is blacklisted'],
        recommendations: ['This site is blacklisted. Do not proceed.'],
        isWhitelisted: false,
        isBlacklisted: true
      }
    }

    if (context.isWhitelisted) {
      return {
        url,
        domain,
        timestamp,
        risk: 'safe',
        riskScore: 0,
        confidence: 1,
        engines: engineResults,
        reasons: ['Domain is whitelisted'],
        recommendations: ['This site is on your whitelist.'],
        isWhitelisted: true,
        isBlacklisted: false
      }
    }

    const assessment = this.computeWeightedScore(engineResults)

    return {
      url,
      domain,
      timestamp,
      risk: assessment.overallRisk,
      riskScore: assessment.overallScore,
      confidence: assessment.confidence,
      engines: engineResults,
      reasons: this.extractTopReasons(engineResults),
      recommendations: this.generateRecommendations(assessment, engineResults),
      certificateInfo: context.certificateInfo,
      domainAge: context.domainAge,
      redirectionChain: context.redirectionChain,
      isWhitelisted: false,
      isBlacklisted: false
    }
  }

  getDetailedAssessment(engineResults: EngineResult[]): RiskAssessment {
    const factors: RiskFactor[] = engineResults
      .filter(e => e.confidence > this.MIN_CONFIDENCE_THRESHOLD && e.score > 0)
      .map(e => ({
        name: e.engineName,
        description: e.reasons[0] || 'No specific reason',
        score: e.score,
        weight: e.engineId === 'phishing-feeds' ? 0.15 :
                e.engineId === 'url-reputation' ? 0.15 :
                e.engineId === 'typosquatting' ? 0.12 :
                e.engineId === 'credential-harvesting' ? 0.12 :
                e.engineId === 'brand-impersonation' ? 0.12 :
                e.engineId === 'homograph' ? 0.10 :
                e.engineId === 'unicode-attack' ? 0.10 :
                e.engineId === 'form-destination' ? 0.10 :
                e.engineId === 'certificate' ? 0.10 :
                e.engineId === 'domain-age' ? 0.08 :
                e.engineId === 'javascript-heuristics' ? 0.08 :
                e.engineId === 'html-structure' ? 0.08 :
                e.engineId === 'redirection-chain' ? 0.08 :
                e.engineId === 'suspicious-tld' ? 0.05 :
                e.engineId === 'hidden-iframe' ? 0.05 :
                e.engineId === 'password-field' ? 0.05 : 0.05,
        contribution: 0,
        risk: getRiskLevel(e.score),
        evidence: e.reasons
      }))

    const totalWeight = factors.reduce((sum, f) => sum + f.weight, 0)
    const normalizedFactors = factors.map(f => ({
      ...f,
      weight: totalWeight > 0 ? f.weight / totalWeight : f.weight,
      contribution: totalWeight > 0 ? (f.score * f.weight) / totalWeight : 0
    }))

    const overallScore = normalizedFactors.reduce((sum, f) => sum + f.contribution, 0)
    const overallRisk = getRiskLevel(overallScore)

    const avgConfidence = engineResults
      .filter(e => e.confidence > 0)
      .reduce((sum, e) => sum + e.confidence, 0) /
      Math.max(1, engineResults.filter(e => e.confidence > 0).length)

    return {
      overallRisk,
      overallScore,
      confidence: avgConfidence,
      factors: normalizedFactors,
      summary: this.generateSummary(overallRisk, overallScore, normalizedFactors),
      timestamp: Date.now()
    }
  }

  private computeWeightedScore(engineResults: EngineResult[]): {
    overallScore: number
    overallRisk: RiskLevel
    confidence: number
  } {
    const relevantResults = engineResults.filter(
      e => e.confidence > this.MIN_CONFIDENCE_THRESHOLD && !e.error
    )

    if (relevantResults.length === 0) {
      return { overallScore: 0, overallRisk: 'safe', confidence: 0 }
    }

    const maxPossibleScore = relevantResults.reduce(
      (sum, r) => sum + r.score * this.getEngineWeight(r.engineId),
      0
    )

    const actualScore = relevantResults.reduce(
      (sum, r) => sum + r.score * this.getEngineWeight(r.engineId),
      0
    )

    const normalizedScore = maxPossibleScore > 0 ? actualScore / maxPossibleScore : 0

    const highConfidenceCount = relevantResults.filter(r => r.confidence >= 0.7).length
    const baseConfidence = Math.min(
      1,
      relevantResults.reduce((sum, r) => sum + r.confidence * this.getEngineWeight(r.engineId), 0) /
        Math.max(1, relevantResults.reduce((sum, r) => sum + this.getEngineWeight(r.engineId), 0))
    )

    const confidenceBoost = Math.min(0.2, highConfidenceCount * 0.03)
    const confidence = Math.min(1, baseConfidence + confidenceBoost)

    const overallRisk = getRiskLevel(normalizedScore)

    return { overallScore: normalizedScore, overallRisk, confidence }
  }

  private getEngineWeight(engineId: string): number {
    const weights: Record<string, number> = {
      'credential-canary': 18,
      'visual-fingerprint': 15,
      'language-matrix': 13,
      'url-entropy': 12,
      'temporal-clustering': 12,
      'css-deception': 10,
      'script-timeseries': 10,
      'certificate-anomaly': 9,
      'interactive-honeypot': 7
    }
    return weights[engineId] || 5
  }

  private extractTopReasons(engineResults: EngineResult[]): string[] {
    const highRiskResults = engineResults
      .filter(e => e.score >= RISK_THRESHOLDS.medium)
      .sort((a, b) => b.score - a.score)

    const reasons: string[] = []
    const seenReasons = new Set<string>()

    for (const result of highRiskResults) {
      for (const reason of result.reasons) {
        const normalized = reason.toLowerCase().trim()
        if (!seenReasons.has(normalized) && reasons.length < 10) {
          seenReasons.add(normalized)
          reasons.push(reason)
        }
      }
    }

    return reasons
  }

  private generateRecommendations(
    assessment: { overallRisk: RiskLevel; overallScore: number },
    engineResults: EngineResult[]
  ): string[] {
    const recommendations: string[] = []

    if (assessment.overallRisk === 'critical') {
      recommendations.push('DO NOT PROCEED: This site is almost certainly a phishing attempt.')
      recommendations.push('Close this tab immediately.')
      recommendations.push('If you reached this site from a link in an email, do not reply to that email.')
    } else if (assessment.overallRisk === 'high') {
      recommendations.push('Strongly recommended to leave this page.')
      recommendations.push('Do not enter any passwords, credit cards, or personal information.')
      recommendations.push('Verify the website URL carefully before proceeding.')
    } else if (assessment.overallRisk === 'medium') {
      recommendations.push('Exercise caution when interacting with this site.')
      recommendations.push('Verify the site legitimacy before entering sensitive data.')
      recommendations.push('Check for HTTPS and valid SSL certificate.')
    } else if (assessment.overallRisk === 'low') {
      recommendations.push('Some minor risk signals detected but site may be safe.')
      recommendations.push('Still verify before entering personal information.')
    }

    const highConfidenceThreats = engineResults.filter(
      e => e.score > 0.6 && e.confidence > 0.7
    )
    if (highConfidenceThreats.length > 0) {
      recommendations.push(
        `High-confidence threat detected by: ${highConfidenceThreats.map(e => e.engineName).join(', ')}`
      )
    }

    if (recommendations.length === 0) {
      recommendations.push('No significant threats detected. Stay safe online.')
    }

    return recommendations
  }

  private generateSummary(
    risk: RiskLevel,
    score: number,
    factors: RiskFactor[]
  ): string {
    const primaryFactors = factors
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 3)

    const riskLabel = risk.charAt(0).toUpperCase() + risk.slice(1)

    if (risk === 'critical') {
      return `CRITICAL: This site exhibits multiple high-confidence phishing indicators. ${primaryFactors.map(f => f.name).join(', ')}. Do not proceed.`
    }
    if (risk === 'high') {
      return `High risk: Strong indicators suggest this may be a phishing site. ${primaryFactors.map(f => f.name).join(', ')}.`
    }
    if (risk === 'medium') {
      return `Medium risk: Some suspicious patterns detected by ${primaryFactors.map(f => f.name).join(', ')}. Proceed with caution.`
    }
    if (risk === 'low') {
      return `Low risk: Minor anomalies detected but overall threat level is low.`
    }
    return 'Safe: No phishing indicators detected.'
  }
}
