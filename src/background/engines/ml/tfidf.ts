import type { TfidfConfig } from '../../../shared/types/models'

export class TfidfVectorizer {
  private config: TfidfConfig | null = null

  async load(modelPath: string): Promise<void> {
    const configUrl = chrome.runtime.getURL(`${modelPath}/tfidf_config.json`)
    const response = await fetch(configUrl)
    this.config = await response.json()
  }

  isLoaded(): boolean {
    return this.config !== null
  }

  transform(text: string): Float32Array {
    const config = this.config!
    const vector = new Float32Array(config.maxFeatures)

    if (!text) return vector

    const tokens = text.split(/\s+/).filter(t => t.length > 0)
    if (tokens.length === 0) return vector

    const termFreq = new Map<string, number>()
    for (const token of tokens) {
      termFreq.set(token, (termFreq.get(token) || 0) + 1)
    }

    const docLen = tokens.length
    for (const [token, count] of termFreq) {
      termFreq.set(token, count / docLen)
    }

    const vocab = config.vocabulary
    const idf = config.idf

    for (const [token, tf] of termFreq) {
      const idx = vocab[token]
      if (idx !== undefined && idx < config.maxFeatures) {
        const tfValue = config.sublinearTf ? 1 + Math.log(tf) : tf
        vector[idx] = tfValue * idf[idx]
      }
    }

    if (config.norm === 'l2') {
      let norm = 0
      for (let i = 0; i < vector.length; i++) {
        norm += vector[i] * vector[i]
      }
      norm = Math.sqrt(norm)
      if (norm > 0) {
        for (let i = 0; i < vector.length; i++) {
          vector[i] /= norm
        }
      }
    }

    return vector
  }

  getConfig(): TfidfConfig | null {
    return this.config
  }

  getTopFeatures(vector: Float32Array, topK: number = 10): Array<{ word: string; score: number }> {
    if (!this.config) return []

    const indexToWord: Record<number, string> = {}
    for (const [word, idx] of Object.entries(this.config.vocabulary)) {
      indexToWord[idx] = word
    }

    const scored: Array<{ word: string; score: number }> = []
    for (let i = 0; i < vector.length; i++) {
      if (vector[i] > 0.1) {
        const word = indexToWord[i]
        if (word) {
          scored.push({ word, score: vector[i] })
        }
      }
    }

    scored.sort((a, b) => b.score - a.score)
    return scored.slice(0, topK)
  }
}
