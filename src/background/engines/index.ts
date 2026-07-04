import { UrlReputationEngine } from './url-reputation'
import { DomainAgeEngine } from './domain-age'
import { TyposquattingEngine } from './typosquatting'
import { HomographEngine } from './homograph'
import { UnicodeAttackEngine } from './unicode-attack'
import { SuspiciousTLDEngine } from './suspicious-tld'
import { CertificateEngine } from './certificate'
import { PhishingFeedsEngine } from './phishing-feeds'
import { JavascriptHeuristicsEngine } from './javascript-heuristics'
import { CredentialHarvestingEngine } from './credential-harvesting'
import { HiddenIframeEngine } from './hidden-iframe'
import { PasswordFieldEngine } from './password-field'
import { BrandImpersonationEngine } from './brand-impersonation'
import { HtmlStructureEngine } from './html-structure'
import { FormDestinationEngine } from './form-destination'
import { RedirectionChainEngine } from './redirection-chain'
import { ScreenshotSimilarityEngine } from './screenshot-similarity'
import type { DetectionEngine, EngineContext, EngineResult } from '../../shared/types/engines'
import type { RiskLevel } from '../../shared/types/analysis'
import { getRiskLevel } from '../../shared/types/analysis'
import { PERFORMANCE_BUDGETS } from '../../shared/constants'

export class EngineManager {
  private engines: Map<string, DetectionEngine> = new Map()
  private engineOrder: string[] = []

  constructor() {
    this.registerEngines()
  }

  private registerEngines(): void {
    const engineInstances: DetectionEngine[] = [
      new UrlReputationEngine(),
      new DomainAgeEngine(),
      new TyposquattingEngine(),
      new HomographEngine(),
      new UnicodeAttackEngine(),
      new SuspiciousTLDEngine(),
      new CertificateEngine(),
      new PhishingFeedsEngine(),
      new JavascriptHeuristicsEngine(),
      new CredentialHarvestingEngine(),
      new HiddenIframeEngine(),
      new PasswordFieldEngine(),
      new BrandImpersonationEngine(),
      new HtmlStructureEngine(),
      new FormDestinationEngine(),
      new RedirectionChainEngine(),
      new ScreenshotSimilarityEngine()
    ]

    for (const engine of engineInstances) {
      this.engines.set(engine.id, engine)
      this.engineOrder.push(engine.id)
    }
  }

  async analyzeAll(context: EngineContext): Promise<EngineResult[]> {
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

    const totalDuration = performance.now() - totalStartTime
    if (totalDuration > PERFORMANCE_BUDGETS.MAX_ANALYSIS_TIME) {
      console.warn(
        `[Seagles Shield] Analysis took ${Math.round(totalDuration)}ms ` +
        `(exceeds budget of ${PERFORMANCE_BUDGETS.MAX_ANALYSIS_TIME}ms)`
      )
    }

    return results
  }

  async analyze(context: EngineContext, engineIds?: string[]): Promise<EngineResult[]> {
    if (engineIds) {
      const results: EngineResult[] = []
      for (const id of engineIds) {
        const engine = this.engines.get(id)
        if (engine) {
          results.push(await engine.analyze(context))
        }
      }
      return results
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
      if (engine instanceof DomainAgeEngine) {
        engine.clearCache()
      }
      if (engine instanceof PhishingFeedsEngine) {
        engine.clearCache()
      }
    }
  }
}

export * from './url-reputation'
export * from './domain-age'
export * from './typosquatting'
export * from './homograph'
export * from './unicode-attack'
export * from './suspicious-tld'
export * from './certificate'
export * from './phishing-feeds'
export * from './javascript-heuristics'
export * from './credential-harvesting'
export * from './hidden-iframe'
export * from './password-field'
export * from './brand-impersonation'
export * from './html-structure'
export * from './form-destination'
export * from './redirection-chain'
export * from './screenshot-similarity'
