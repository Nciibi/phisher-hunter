import { BaseEngine } from '../base-engine'
import type { EngineContext, EngineResult } from '../../../shared/types/engines'
import type { ModelConfig, InferenceResult, ModelStatus } from '../../../shared/types/models'
import { PERFORMANCE_BUDGETS } from '../../../shared/constants'

export abstract class MLModelEngine extends BaseEngine {
  protected abstract modelConfig: ModelConfig
  protected model: any = null
  protected tfjsInitialized = false

  protected stats = {
    totalInferences: 0,
    totalLatencyMs: 0,
    totalErrors: 0,
    lastInferenceTime: 0
  }

  private loadInProgress = false
  private loadResolver: (() => void) | null = null

  protected abstract runMLInference(context: EngineContext): Promise<InferenceResult>
  protected abstract preprocess(context: EngineContext): Promise<any>

  protected postprocess(modelOutput: any): InferenceResult {
    const score = modelOutput.dataSync()[0]
    const confidence = Math.min(1, Math.abs(score - 0.5) * 2)
    return {
      score,
      confidence,
      latencyMs: 0,
      status: 'success'
    }
  }

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    if (!this.tfjsInitialized) {
      const initOk = await this.initializeTFJS()
      if (!initOk) {
        return this.handleModelError(new Error('TF.js initialization failed'))
      }
    }

    if (!this.model) {
      const loadOk = await this.loadModel()
      if (!loadOk) {
        return this.handleModelError(new Error('Model failed to load'))
      }
    }

    try {
      const result = await this.runWithTimeout(context)

      this.stats.totalInferences++
      this.stats.totalLatencyMs += result.latencyMs
      this.stats.lastInferenceTime = Date.now()

      return this.createResult(
        result.score,
        result.confidence,
        this.buildReasons(result),
        this.buildRecommendation(result),
        {
          modelVersion: this.modelConfig.version,
          latencyMs: result.latencyMs,
          modelStatus: result.status,
          ...result.details
        }
      )
    } catch (error) {
      this.stats.totalErrors++
      return this.handleModelError(error)
    }
  }

  protected async initializeTFJS(): Promise<boolean> {
    try {
      const tf = await this.importTFJS()
      const backends = ['webgl', 'cpu']
      let backendSet = false

      for (const backend of backends) {
        try {
          if (backend === 'webgl') {
            await tf.setBackend('webgl')
          } else {
            await tf.setBackend('cpu')
          }
          await tf.ready()
          backendSet = true
          break
        } catch {
          continue
        }
      }

      if (!backendSet) {
        return false
      }

      this.tfjsInitialized = true
      return true
    } catch {
      return false
    }
  }

  protected async importTFJS(): Promise<any> {
    const tf = await import('@tensorflow/tfjs-core')
    await import('@tensorflow/tfjs-backend-cpu')
    try {
      await import('@tensorflow/tfjs-backend-webgl')
    } catch {
      // WebGL not available, CPU fallback
    }
    const converter = await import('@tensorflow/tfjs-converter')
    return { ...tf, loadGraphModel: converter.loadGraphModel }
  }

  private async loadModel(): Promise<boolean> {
    if (this.loadInProgress) {
      return new Promise(resolve => {
        this.loadResolver = resolve
      })
    }

    this.loadInProgress = true
    try {
      const tf = await this.importTFJS()
      const modelUrl = chrome.runtime.getURL(this.modelConfig.path)
      this.model = await tf.loadGraphModel(modelUrl)

      const dummyInput = tf.zeros(this.modelConfig.inputShape, 'int32')
      await this.model.predictAsync(dummyInput)
      dummyInput.dispose()

      return true
    } catch {
      this.model = null
      return false
    } finally {
      this.loadInProgress = false
      if (this.loadResolver) {
        this.loadResolver()
        this.loadResolver = null
      }
    }
  }

  private async runWithTimeout(context: EngineContext): Promise<InferenceResult> {
    const timeoutMs = PERFORMANCE_BUDGETS.MAX_ENGINE_TIME

    const inferencePromise = this.runMLInference(context)
    const timeoutPromise = new Promise<InferenceResult>((_, reject) => {
      setTimeout(() => reject(new Error('Inference timed out')), timeoutMs)
    })

    return Promise.race([inferencePromise, timeoutPromise])
  }

  private handleModelError(error: unknown): EngineResult {
    const errorMessage = error instanceof Error ? error.message : String(error)

    if (this.model) {
      try { this.model.dispose() } catch { /* ignore */ }
      this.model = null
    }

    return {
      engineId: this.id,
      engineName: this.name,
      score: 0,
      confidence: 0,
      risk: 'safe',
      reasons: [`ML model unavailable: ${errorMessage}. Using safe default.`],
      recommendation: 'ML analysis unavailable due to model error',
      duration: 0,
      details: {
        modelVersion: this.modelConfig.version,
        error: errorMessage,
        fallback: true
      }
    }
  }

  protected buildReasons(result: InferenceResult): string[] {
    const reasons: string[] = []

    if (result.score > 0.7) {
      reasons.push(`${this.name} detected strong phishing signals (score: ${result.score.toFixed(2)})`)
    } else if (result.score > 0.4) {
      reasons.push(`${this.name} detected suspicious patterns (score: ${result.score.toFixed(2)})`)
    }

    if (result.details) {
      for (const value of Object.values(result.details)) {
        if (typeof value === 'string') {
          reasons.push(value)
        }
      }
    }

    if (reasons.length === 0 && result.score > 0.2) {
      reasons.push(`${this.name} flagged minor anomalies`)
    }

    return reasons
  }

  protected buildRecommendation(result: InferenceResult): string {
    if (result.score > 0.7) {
      return `${this.name} strongly indicates this is a phishing site. Model confidence: ${(result.confidence * 100).toFixed(0)}%`
    }
    if (result.score > 0.4) {
      return `${this.name} suggests caution. Additional signals needed for definitive classification.`
    }
    return `${this.name} found no significant ML-based risk signals.`
  }

  getStatus(): ModelStatus {
    return {
      id: this.id,
      name: this.name,
      loaded: this.model !== null,
      version: this.modelConfig.version,
      lastInference: this.stats.lastInferenceTime,
      totalInferences: this.stats.totalInferences,
      averageLatencyMs: this.stats.totalInferences > 0
        ? Math.round(this.stats.totalLatencyMs / this.stats.totalInferences)
        : 0,
      errorCount: this.stats.totalErrors,
      memoryBytes: this.modelConfig.memoryEstimateBytes
    }
  }

  unloadModel(): void {
    if (this.model) {
      try { this.model.dispose() } catch { /* ignore */ }
      this.model = null
    }
    this.tfjsInitialized = false
  }

  clearCache(): void {
    // No ML result caching by default
  }
}
