import { useState, useEffect, useCallback } from 'react'
import type { AnalysisResult } from '../../shared/types/analysis'
import type { ExtensionMessage } from '../../shared/types/messages'

export function useRiskAnalysis(url: string | undefined) {
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const analyze = useCallback(async () => {
    if (!url) return
    setLoading(true)
    setError(null)

    try {
      const message: ExtensionMessage = {
        type: 'ANALYZE_URL',
        payload: { url },
        requestId: crypto.randomUUID(),
        timestamp: Date.now()
      }

      const response = await chrome.runtime.sendMessage(message)
      if (response.success) {
        setAnalysis(response.data)
      } else {
        setError(response.error || 'Analysis failed')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze URL')
    } finally {
      setLoading(false)
    }
  }, [url])

  useEffect(() => {
    analyze()
  }, [analyze])

  const refresh = useCallback(() => {
    analyze()
  }, [analyze])

  return { analysis, loading, error, refresh }
}
