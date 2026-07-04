import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

export class ScreenshotSimilarityEngine extends BaseEngine {
  id = 'screenshot-similarity'
  name = 'Screenshot Similarity Analysis'
  description = 'Compares page screenshots against known legitimate sites (requires fetch)'
  version = '1.0.0'
  weight = 10
  enabled = false

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    return this.createResult(0, 0, [
      'Screenshot similarity engine is disabled - requires API access'
    ], 'Enable screenshot comparison in settings for visual phishing detection.', {
      requiresApiAccess: true,
      disabledByDefault: true
    })
  }
}
