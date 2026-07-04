import { MLModelEngine } from './ml-model-engine'
import { TfidfVectorizer } from './tfidf'
import type { EngineContext, EngineResult } from '../../../shared/types/engines'
import type { ModelConfig, InferenceResult } from '../../../shared/types/models'

export class DomMLModelEngine extends MLModelEngine {
  id = 'dom-ml'
  name = 'DOM Content ML'
  description = 'TF-IDF + Neural Network analysis of page text content'
  version = '1.0.0'
  weight = 18

  protected modelConfig: ModelConfig = {
    id: 'dom-classifier',
    name: 'DOM Text Classifier',
    version: '1.0.0',
    path: 'models/dom-classifier/model.json',
    inputShape: [1, 5000],
    outputShape: [1, 1],
    threshold: 0.5,
    memoryEstimateBytes: 250 * 1024,
    eagerLoad: false,
    preferredBackend: 'cpu'
  }

  private tfidf: TfidfVectorizer = new TfidfVectorizer()

  protected async preprocess(context: EngineContext): Promise<Float32Array> {
    const rawHtml = context.html || context.pageText || ''
    const visibleText = this.extractVisibleText(rawHtml)

    if (!this.tfidf.isLoaded()) {
      await this.tfidf.load('models/dom-classifier')
    }

    return this.tfidf.transform(visibleText)
  }

  private extractVisibleText(html: string): string {
    if (!html) return ''

    let text = html
    text = text.replace(/<script[\s\S]*?<\/script>/gi, ' ')
    text = text.replace(/<style[\s\S]*?<\/style>/gi, ' ')
    text = text.replace(/<svg[\s\S]*?<\/svg>/gi, ' ')
    text = text.replace(/<[^>]+>/g, ' ')
    text = text.replace(/&amp;/g, '&')
    text = text.replace(/&lt;/g, '<')
    text = text.replace(/&gt;/g, '>')
    text = text.replace(/&quot;/g, '"')
    text = text.replace(/&#39;/g, "'")
    text = text.replace(/&#x27;/g, "'")
    text = text.replace(/\s+/g, ' ').trim()
    text = text.toLowerCase()
    text = text.replace(/[^a-z0-9\s@.\/-]/g, ' ')
    text = text.replace(/\s+/g, ' ').trim()

    return text.slice(0, 10000)
  }

  protected async runMLInference(context: EngineContext): Promise<InferenceResult> {
    const startTime = performance.now()

    const inputVector = await this.preprocess(context)

    const tf = await this.importTFJS()
    const input = tf.tensor(inputVector, [1, this.modelConfig.inputShape[1]], 'float32')

    try {
      const output = await this.model.predictAsync(input)
      const score = output.dataSync()[0]

      input.dispose()
      output.dispose()

      const latencyMs = performance.now() - startTime
      const confidence = Math.min(1, Math.abs(score - 0.5) * 2)
      const details = this.extractKeyPhrases(context, inputVector)

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

  private extractKeyPhrases(context: EngineContext, vector: Float32Array): Record<string, unknown> {
    const topWords = this.tfidf.getTopFeatures(vector, 5)
    const wordList = topWords.map(w => w.word)

    const phishingIndicators: string[] = []
    const text = this.extractVisibleText(context.html || '').toLowerCase()

    const urgencyWords = ['urgent', 'immediately', 'suspended', 'limited', 'expires soon', 'action required', 'time sensitive']
    const credentialWords = ['verify', 'password', 'sign in', 'log in', 'credentials', 'account', 'confirm your']
    const brandWords = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'bank', 'wells fargo', 'chase', 'capital one']

    for (const word of urgencyWords) {
      if (text.includes(word)) phishingIndicators.push(`Urgency language: "${word}"`)
    }
    for (const word of credentialWords) {
      if (text.includes(word)) phishingIndicators.push(`Credential harvesting language: "${word}"`)
    }
    for (const word of brandWords) {
      if (wordList.includes(word)) phishingIndicators.push(`Brand reference detected: "${word}"`)
    }

    const wordCount = text.split(/\s+/).filter(Boolean).length

    return {
      topTfidfWords: wordList,
      phishingIndicators: phishingIndicators.slice(0, 5),
      wordCount
    }
  }

  protected buildReasons(result: InferenceResult): string[] {
    const reasons = super.buildReasons(result)

    if (result.details?.phishingIndicators) {
      const indicators = result.details.phishingIndicators as string[]
      for (const indicator of indicators.slice(0, 3)) {
        if (!reasons.includes(indicator)) {
          reasons.push(indicator)
        }
      }
    }

    if (result.details?.topTfidfWords) {
      const words = (result.details.topTfidfWords as string[]).slice(0, 3)
      if (words.length > 0) {
        reasons.push(`Key suspicious terms: "${words.join('", "')}"`)
      }
    }

    return reasons
  }
}
