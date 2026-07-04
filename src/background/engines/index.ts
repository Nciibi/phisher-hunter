import { CredentialCanaryEngine } from './credential-canary'
import { VisualFingerprintEngine } from './visual-fingerprint'
import { UrlEntropyEngine } from './url-entropy'
import { CssDeceptionEngine } from './css-deception'
import { LanguageMatrixEngine } from './language-matrix'
import { ScriptTimeseriesEngine } from './script-timeseries'
import { CertificateAnomalyEngine } from './certificate-anomaly'
import { TemporalClusteringEngine } from './temporal-clustering'
import { InteractiveHoneypotEngine } from './interactive-honeypot'
import { UrlMLModelEngine } from './ml/url-ml-engine'
import { DomMLModelEngine } from './ml/dom-ml-engine'
import { EnsembleEngine } from './ml/ensemble-engine'
import { MLModelEngine } from './ml/ml-model-engine'
import type { DetectionEngine, EngineContext, EngineResult } from '../../shared/types/engines'
import type { RiskLevel } from '../../shared/types/analysis'
import type { EnsembleResult, MLSubsystemStatus, ModelStatus } from '../../shared/types/models'
import { getRiskLevel } from '../../shared/types/analysis'
import { PERFORMANCE_BUDGETS } from '../../shared/constants'

export class EngineManager {
  private engines: Map<string, DetectionEngine> = new Map()
  private engineOrder: string[] = []
  private ensemble: EnsembleEngine = new EnsembleEngine()

  constructor() {
    this.registerEngines()
  }

  private registerEngines(): void {
    const engineInstances: DetectionEngine[] = [
      new CredentialCanaryEngine(),
      new VisualFingerprintEngine(),
      new UrlEntropyEngine(),
      new CssDeceptionEngine(),
      new LanguageMatrixEngine(),
      new ScriptTimeseriesEngine(),
      new CertificateAnomalyEngine(),
      new TemporalClusteringEngine(),
      new InteractiveHoneypotEngine(),
      new UrlMLModelEngine(),
      new DomMLModelEngine()
    ]

    for (const engine of engineInstances) {
      this.engines.set(engine.id, engine)
      this.engineOrder.push(engine.id)
    }
  }

  async analyzeAll(context: EngineContext): Promise<{
    engineResults: EngineResult[]
    ensembleResult: EnsembleResult
  }> {
    const results: EngineResult[] = []
    const totalStartTime = performance.now()

    const runEngine = async (engine: DetectionEngine): Promise<EngineResult> => {
      const engineStartTime = performance.now()
      try {
        const result = await engine.analyze(context)
        result.duration = performance.now() - engineStartTime
        return result
      } catch (error) {
        const duration = performance.now() - engineStartTime
        return {
          engineId: engine.id,
          engineName: engine.name,
          score: 0,
          confidence: 0,
          risk: 'safe' as RiskLevel,
          reasons: [`Engine crashed: ${error instanceof Error ? error.message : String(error)}`],
          recommendation: 'Engine encountered a fatal error',
          duration,
          error: error instanceof Error ? error.message : String(error)
        }
      }
    }

    const enginePromises = this.engineOrder
      .map(id => this.engines.get(id)!)
      .map(engine => runEngine(engine))

    const settled = await Promise.allSettled(enginePromises)

    for (const result of settled) {
      if (result.status === 'fulfilled') {
        results.push(result.value)
      } else {
        results.push({
          engineId: 'unknown',
          engineName: 'Unknown Engine',
          score: 0,
          confidence: 0,
          risk: 'safe' as RiskLevel,
          reasons: ['Engine promise rejected'],
          recommendation: 'Engine failed to execute',
          duration: 0,
          error: result.reason instanceof Error ? result.reason.message : String(result.reason)
        })
      }
    }

    const ensembleResult = this.ensemble.computeEnsemble(results)

    const totalDuration = performance.now() - totalStartTime
    if (totalDuration > PERFORMANCE_BUDGETS.MAX_ANALYSIS_TIME) {
      console.warn(
        `[Phisher Hunter] Analysis took ${Math.round(totalDuration)}ms ` +
        `(exceeds budget of ${PERFORMANCE_BUDGETS.MAX_ANALYSIS_TIME}ms)`
      )
    }

    return { engineResults: results, ensembleResult }
  }

  async analyze(context: EngineContext, engineIds?: string[]): Promise<{ engineResults: EngineResult[]; ensembleResult: EnsembleResult }> {
    if (engineIds) {
      const results: EngineResult[] = []
      for (const id of engineIds) {
        const engine = this.engines.get(id)
        if (engine) {
          results.push(await engine.analyze(context))
        }
      }
      const ensembleResult = this.ensemble.computeEnsemble(results)
      return { engineResults: results, ensembleResult }
    }
    return this.analyzeAll(context)
  }

  getEngine(id: string): DetectionEngine | undefined {
    return this.engines.get(id)
  }

  getAllEngines(): DetectionEngine[] {
    return this.engineOrder.map(id => this.engines.get(id)!)
  }

  getEnabledEngines(): DetectionEngine[] {
    return this.getAllEngines().filter(e => e.enabled)
  }

  setEngineEnabled(id: string, enabled: boolean): boolean {
    const engine = this.engines.get(id)
    if (engine) {
      engine.enabled = enabled
      return true
    }
    return false
  }

  setEngineWeight(id: string, weight: number): boolean {
    const engine = this.engines.get(id)
    if (engine) {
      engine.weight = weight
      return true
    }
    return false
  }

  getEngineStatus(): Array<{ id: string; name: string; enabled: boolean; weight: number }> {
    return this.getAllEngines().map(e => ({
      id: e.id,
      name: e.name,
      enabled: e.enabled,
      weight: e.weight
    }))
  }

  getActiveEngineCount(): number {
    return this.getEnabledEngines().length
  }

  clearAllCaches(): void {
    for (const engine of this.engines.values()) {
      if (typeof (engine as any).clearCache === 'function') {
        ;(engine as any).clearCache()
      }
    }
  }
}

export * from './credential-canary'
export * from './visual-fingerprint'
export * from './url-entropy'
export * from './css-deception'
export * from './language-matrix'
export * from './script-timeseries'
export * from './certificate-anomaly'
export * from './temporal-clustering'
export * from './interactive-honeypot'
