import type { EngineResult } from '../../../shared/types/engines'
import type { EnsembleConfig, EnsembleResult, EngineContribution } from '../../../shared/types/models'
import { ML_MODEL_PATHS } from '../../../shared/constants'

export class EnsembleEngine {
  private config: EnsembleConfig | null = null

  private static readonly FALLBACK_WEIGHTS: Record<string, number> = {
    'url-ml': 0.22,
    'credential-canary': 0.18,
    'dom-ml': 0.16,
    'visual-fingerprint': 0.12,
    'language-matrix': 0.10,
    'url-entropy': 0.08,
    'temporal-clustering': 0.05,
    'css-deception': 0.04,
    'script-timeseries': 0.03,
    'certificate-anomaly': 0.02,
    'interactive-honeypot': 0.02,
  }

  private static readonly FALLBACK_BIAS = -0.5

  private mode: 'learned' | 'static_fallback' = 'static_fallback'

  constructor() {
    this.loadConfig()
  }

  private async loadConfig(): Promise<void> {
    try {
      const configUrl = chrome.runtime.getURL(ML_MODEL_PATHS.ENSEMBLE_WEIGHTS)
      const response = await fetch(configUrl)
      this.config = await response.json()
      this.mode = 'learned'
    } catch {
      this.mode = 'static_fallback'
    }
  }

  computeEnsemble(engineResults: EngineResult[]): EnsembleResult {
    const weights = this.config?.weights ?? EnsembleEngine.FALLBACK_WEIGHTS
    const bias = this.config?.bias ?? EnsembleEngine.FALLBACK_BIAS

    let logit = bias
    const contributions: EngineContribution[] = []

    for (const result of engineResults) {
      const weight = weights[result.engineId]
      if (weight === undefined) continue

      const contribution = result.score * weight
      logit += contribution

      contributions.push({
        engineId: result.engineId,
        engineName: result.engineName,
        score: result.score,
        weight,
        contribution,
        contributionPercent: 0
      })
    }

    const score = 1 / (1 + Math.exp(-logit))

    const totalPositive = contributions.reduce((sum, c) => sum + Math.max(0, c.contribution), 0)
    const totalNegative = contributions.reduce((sum, c) => sum + Math.max(0, -c.contribution), 0)

    for (const c of contributions) {
      const total = c.contribution >= 0 ? totalPositive : totalNegative
      c.contributionPercent = total > 0 ? (Math.abs(c.contribution) / total) * 100 : 0
    }

    const confidence = this.computeConfidence(contributions, score)

    return {
      score,
      confidence,
      contributions,
      mode: this.mode
    }
  }

  private computeConfidence(contributions: EngineContribution[], score: number): number {
    const boundaryDistance = Math.abs(score - 0.5)

    const positiveCount = contributions.filter(c => c.score > 0.5).length
    const totalCount = contributions.filter(c => c.score >= 0).length
    const agreement = totalCount > 0
      ? Math.max(positiveCount, totalCount - positiveCount) / totalCount
      : 0

    const mlEngines = contributions.filter(c => c.engineId === 'url-ml' || c.engineId === 'dom-ml')
    const mlParticipated = mlEngines.filter(c => c.score >= 0).length
    const mlBonus = mlEngines.length > 0 ? (mlParticipated / mlEngines.length) * 0.1 : 0

    return Math.min(1, boundaryDistance * 1.5 + agreement * 0.3 + mlBonus)
  }

  getStatus(): { mode: 'learned' | 'static_fallback'; version: string } {
    return {
      mode: this.mode,
      version: this.config?.version ?? 'fallback'
    }
  }

  async reloadConfig(): Promise<void> {
    this.config = null
    await this.loadConfig()
  }
}
