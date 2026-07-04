import type { DetectionEngine, EngineContext, EngineResult } from '../../shared/types/engines'
import type { RiskLevel } from '../../shared/types/analysis'
import { getRiskLevel } from '../../shared/types/analysis'

export abstract class BaseEngine implements DetectionEngine {
  abstract id: string
  abstract name: string
  abstract description: string
  abstract version: string

  enabled: boolean = true
  weight: number = 1

  async analyze(context: EngineContext): Promise<EngineResult> {
    const startTime = performance.now()
    try {
      if (!this.enabled) {
        return this.createSkipResult('Engine disabled')
      }
      const result = await this.runAnalysis(context)
      result.duration = performance.now() - startTime
      return result
    } catch (error) {
      const duration = performance.now() - startTime
      return this.createErrorResult(error, duration)
    }
  }

  protected abstract runAnalysis(context: EngineContext): Promise<EngineResult>

  protected createResult(
    score: number,
    confidence: number,
    reasons: string[],
    recommendation: string,
    details?: Record<string, unknown>
  ): EngineResult {
    return {
      engineId: this.id,
      engineName: this.name,
      score: Math.max(0, Math.min(1, score)),
      confidence: Math.max(0, Math.min(1, confidence)),
      risk: getRiskLevel(score),
      reasons,
      recommendation,
      details,
      duration: 0
    }
  }

  protected createSkipResult(reason: string): EngineResult {
    return {
      engineId: this.id,
      engineName: this.name,
      score: 0,
      confidence: 0,
      risk: 'safe',
      reasons: [reason],
      recommendation: 'No analysis performed',
      duration: 0
    }
  }

  protected createErrorResult(error: unknown, duration: number): EngineResult {
    const message = error instanceof Error ? error.message : String(error)
    return {
      engineId: this.id,
      engineName: this.name,
      score: 0,
      confidence: 0,
      risk: 'safe',
      reasons: [`Analysis error: ${message}`],
      recommendation: 'Unable to complete analysis due to an error',
      duration,
      error: message
    }
  }
}
