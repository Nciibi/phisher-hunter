export interface ModelConfig {
  id: string
  name: string
  version: string
  path: string
  inputShape: number[]
  outputShape: number[]
  threshold: number
  memoryEstimateBytes: number
  eagerLoad: boolean
  preferredBackend: 'cpu' | 'webgl' | 'wasm'
}

export interface InferenceResult {
  score: number
  confidence: number
  latencyMs: number
  details?: Record<string, unknown>
  status: 'success' | 'fallback' | 'error'
  error?: string
}

export interface EnsembleConfig {
  version: string
  weights: Record<string, number>
  bias: number
  threshold: number
  trainDate: string
  accuracy?: number
  aucRoc?: number
}

export interface EnsembleResult {
  score: number
  confidence: number
  contributions: EngineContribution[]
  mode: 'learned' | 'static_fallback'
}

export interface EngineContribution {
  engineId: string
  engineName: string
  score: number
  weight: number
  contribution: number
  contributionPercent: number
}

export interface CharTokenizerConfig {
  charToId: Record<string, number>
  idToChar: Record<number, string>
  maxLength: number
  vocabSize: number
  specialTokens: {
    padding: number
    unknown: number
    start: number
    end: number
  }
}

export interface TfidfConfig {
  vocabulary: Record<string, number>
  idf: number[]
  maxFeatures: number
  sublinearTf: boolean
  norm: 'l1' | 'l2' | null
}

export interface MLSubsystemStatus {
  tfjsLoaded: boolean
  availableBackends: string[]
  activeBackend: string
  models: ModelStatus[]
  totalMemoryBytes: number
  ensembleMode: 'learned' | 'static_fallback'
}

export interface ModelStatus {
  id: string
  name: string
  loaded: boolean
  version: string
  lastInference?: number
  totalInferences: number
  averageLatencyMs: number
  errorCount: number
  memoryBytes: number
}

export class MLModelError extends Error {
  constructor(
    message: string,
    public readonly modelId: string,
    public readonly code: 'LOAD_FAILED' | 'INFERENCE_FAILED' | 'TIMEOUT' | 'OOM' | 'BACKEND_UNAVAILABLE'
  ) {
    super(`[ML:${modelId}] ${message}`)
    this.name = 'MLModelError'
  }
}
