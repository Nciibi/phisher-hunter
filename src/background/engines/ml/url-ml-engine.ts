import { MLModelEngine } from './ml-model-engine'
import type { EngineContext, EngineResult } from '../../../shared/types/engines'
import type { ModelConfig, InferenceResult, CharTokenizerConfig } from '../../../shared/types/models'

export class UrlMLModelEngine extends MLModelEngine {
  id = 'url-ml'
  name = 'URL ML Model'
  description = 'Character-level CNN trained to detect phishing patterns in URLs'
  version = '1.0.0'
  weight = 20

  protected modelConfig: ModelConfig = {
    id: 'url-cnn',
    name: 'URL Character CNN',
    version: '1.0.0',
    path: 'models/url-cnn/model.json',
    inputShape: [1, 200],
    outputShape: [1, 1],
    threshold: 0.5,
    memoryEstimateBytes: 300 * 1024,
    eagerLoad: false,
    preferredBackend: 'webgl'
  }

  private tokenizerConfig: CharTokenizerConfig = {
    charToId: {},
    idToChar: {},
    maxLength: 200,
    vocabSize: 128,
    specialTokens: {
      padding: 0,
      unknown: 58,
      start: 59,
      end: 60
    }
  }

  constructor() {
    super()
    this.buildTokenizer()
  }

  private buildTokenizer(): void {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789.-_/?=&%~:@!$\'()*+,;#'
    for (let i = 0; i < chars.length; i++) {
      const id = i + 1
      this.tokenizerConfig.charToId[chars[i]] = id
      this.tokenizerConfig.idToChar[id] = chars[i]
    }
  }

  protected async preprocess(context: EngineContext): Promise<Uint32Array> {
    let url = context.url.toLowerCase()
    url = url.replace(/^https?:\/\//, '')
    url = url.replace(/^www\./, '')

    if (url.length > this.tokenizerConfig.maxLength) {
      url = url.substring(0, this.tokenizerConfig.maxLength)
    }

    const input = new Uint32Array(this.tokenizerConfig.maxLength)
    for (let i = 0; i < url.length; i++) {
      input[i] = this.tokenizerConfig.charToId[url[i]] ?? this.tokenizerConfig.specialTokens.unknown
    }

    return input
  }

  protected async runMLInference(context: EngineContext): Promise<InferenceResult> {
    const startTime = performance.now()

    const inputTensor = await this.preprocess(context)

    const tf = await this.importTFJS()
    const input = tf.tensor(inputTensor, [1, this.tokenizerConfig.maxLength], 'int32')

    try {
      const output = await this.model.predictAsync(input)
      const score = output.dataSync()[0]

      input.dispose()
      output.dispose()

      const latencyMs = performance.now() - startTime
      const confidence = Math.min(1, Math.abs(score - 0.5) * 2)
      const details = this.extractAttributions(context, score)

      return {
        score,
        confidence,
        latencyMs,
        status: 'success',
        details
      }
    } catch (error) {
      input.dispose()
      throw error
    }
  }

  private extractAttributions(context: EngineContext, score: number): Record<string, unknown> {
    const attributions: string[] = []

    const digitCount = (context.hostname.match(/\d/g) || []).length
    if (digitCount > 2) {
      attributions.push(`Domain contains ${digitCount} digits — possible brand impersonation`)
    }

    const suspiciousTlds = new Set(['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.review', '.win', '.bid', '.life', '.download', '.stream', '.racing', '.party', '.faith', '.date', '.loan', '.men', '.accountant', '.country', '.mom', '.lol', '.pics', '.gdn', '.host', '.press', '.website', '.space', '.tech', '.fun', '.icu', '.cyou'])
    if (context.tld && suspiciousTlds.has(context.tld)) {
      attributions.push(`Suspicious TLD: ${context.tld}`)
    }

    if (context.subdomains.length > 3) {
      attributions.push(`Unusual number of subdomains (${context.subdomains.length})`)
    }

    const url = context.url.toLowerCase()
    if (/bit\.ly|tinyurl|goo\.gl|shorturl|t\.co|ow\.ly|is\.gd|buff\.ly|rb\.gy/i.test(url)) {
      attributions.push('URL shortener detected — common in phishing campaigns')
    }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(context.hostname)) {
      attributions.push('IP address used instead of domain name')
    }

    if (/\/\/+/.test(context.path)) {
      attributions.push('Multiple consecutive slashes in path — URL manipulation detected')
    }

    if (attributions.length === 0) {
      attributions.push(`URL pattern analysis: score = ${score.toFixed(3)}`)
    }

    return {
      contributingFactors: attributions,
      rawScore: score
    }
  }

  protected buildReasons(result: InferenceResult): string[] {
    const reasons = super.buildReasons(result)

    if (result.details?.contributingFactors) {
      const factors = result.details.contributingFactors as string[]
      for (const factor of factors.slice(0, 3)) {
        if (!reasons.includes(factor)) {
          reasons.push(factor)
        }
      }
    }

    return reasons
  }
}
