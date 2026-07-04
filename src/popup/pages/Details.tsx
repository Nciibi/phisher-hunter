import { useCurrentTab } from '../hooks/useCurrentTab'
import { useRiskAnalysis } from '../hooks/useRiskAnalysis'
import { getRiskColor, getRiskLabel } from '../../shared/types/analysis'
import type { EngineResult } from '../../shared/types/engines'

export default function DetailsPage() {
  const tab = useCurrentTab()
  const { analysis, loading } = useRiskAnalysis(tab?.url)

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[500px]">
        <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!analysis) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[500px] p-8 text-center">
        <p className="text-secondary text-sm">No analysis data available.</p>
        <a href="#/" className="mt-3 text-sm text-blue-500 hover:underline">Back</a>
      </div>
    )
  }

  const sortedEngines = [...analysis.engines].sort((a, b) => b.score - a.score)

  return (
    <div className="flex flex-col min-h-[500px]">
      <div className="px-4 py-3 border-b border-[var(--border)] flex items-center gap-3">
        <a href="#/" className="text-blue-500 hover:underline text-sm">
          ← Back
        </a>
        <h1 className="text-base font-semibold text-[var(--text-primary)]">Engine Details</h1>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
        <div className="bg-[var(--bg-secondary)] rounded-xl p-4">
          <div className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            Summary
          </div>
          <div className="grid grid-cols-3 gap-3 text-center">
            <div>
              <div className="text-lg font-bold" style={{ color: getRiskColor(analysis.risk) }}>
                {analysis.risk.toUpperCase()}
              </div>
              <div className="text-xs text-[var(--text-tertiary)]">Risk Level</div>
            </div>
            <div>
              <div className="text-lg font-bold text-[var(--text-primary)]">
                {Math.round(analysis.riskScore * 100)}%
              </div>
              <div className="text-xs text-[var(--text-tertiary)]">Score</div>
            </div>
            <div>
              <div className="text-lg font-bold text-[var(--text-primary)]">
                {Math.round(analysis.confidence * 100)}%
              </div>
              <div className="text-xs text-[var(--text-tertiary)]">Confidence</div>
            </div>
          </div>
        </div>

        <div className="bg-[var(--bg-secondary)] rounded-xl p-4">
          <div className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            All Engines ({sortedEngines.length})
          </div>
          <div className="space-y-2">
            {sortedEngines.map(engine => (
              <EngineResultCard key={engine.engineId} engine={engine} />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function EngineResultCard({ engine }: { engine: EngineResult }) {
  const color = getRiskColor(engine.risk)

  return (
    <div className="bg-[var(--bg-primary)] rounded-lg p-3 border border-[var(--border)]">
      <div className="flex items-start justify-between mb-1">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
          <span className="text-sm font-medium text-[var(--text-primary)]">
            {engine.engineName}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {engine.error ? (
            <span className="text-xs text-red-500">Error</span>
          ) : (
            <span className="text-sm font-semibold" style={{ color }}>
              {Math.round(engine.score * 100)}%
            </span>
          )}
        </div>
      </div>

      {engine.reasons.length > 0 && (
        <ul className="space-y-0.5 ml-4 mt-1">
          {engine.reasons.slice(0, 2).map((reason, i) => (
            <li key={i} className="text-xs text-[var(--text-secondary)]">{reason}</li>
          ))}
        </ul>
      )}

      <div className="flex items-center gap-3 mt-1.5 text-xs text-[var(--text-tertiary)]">
        <span>Confidence: {Math.round(engine.confidence * 100)}%</span>
        <span>Duration: {Math.round(engine.duration)}ms</span>
        {engine.error && <span className="text-red-500">{engine.error}</span>}
      </div>
    </div>
  )
}
