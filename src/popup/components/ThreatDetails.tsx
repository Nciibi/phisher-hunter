import type { AnalysisResult } from '../../shared/types/analysis'
import { getRiskColor } from '../../shared/types/analysis'

interface ThreatDetailsProps {
  analysis: AnalysisResult
}

export default function ThreatDetails({ analysis }: ThreatDetailsProps) {
  const highRiskEngines = analysis.engines.filter(e => e.score > 0.3).sort((a, b) => b.score - a.score)
  const showAll = analysis.engines.length > 0
  const levelColor = getRiskColor(analysis.risk)

  return (
    <div className="space-y-2">
      {analysis.reasons.length > 0 && (
        <div className="bg-[var(--bg-secondary)] rounded-xl p-4">
          <div className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            {analysis.reasons.length === 1 ? 'Reason' : `Top Reasons (${analysis.reasons.length})`}
          </div>
          <ul className="space-y-1.5">
            {analysis.reasons.slice(0, 5).map((reason, i) => (
              <li key={i} className="flex gap-2 text-sm text-[var(--text-primary)]">
                <span className="text-red-500 flex-shrink-0 mt-0.5">•</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {analysis.recommendations.length > 0 && (
        <div className="bg-[var(--bg-secondary)] rounded-xl p-4">
          <div className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            Recommendations
          </div>
          <ul className="space-y-1.5">
            {analysis.recommendations.map((rec, i) => (
              <li key={i} className="flex gap-2 text-sm" style={{ color: analysis.risk === 'safe' ? 'var(--safe)' : '#fb8c00' }}>
                <span className="flex-shrink-0 mt-0.5">{analysis.risk === 'safe' ? '✓' : '→'}</span>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {showAll && highRiskEngines.length > 0 && (
        <div className="bg-[var(--bg-secondary)] rounded-xl p-4">
          <div className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            Engine Results
          </div>
          <div className="space-y-2">
            {highRiskEngines.slice(0, 5).map(engine => (
              <div key={engine.engineId} className="flex items-center gap-3">
                <div
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: getRiskColor(engine.risk) }}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-[var(--text-primary)] truncate">
                    {engine.engineName}
                  </div>
                  <div className="text-xs text-[var(--text-tertiary)] truncate">
                    {engine.reasons[0] || 'No details'}
                  </div>
                </div>
                <div className="text-xs font-semibold" style={{ color: getRiskColor(engine.risk) }}>
                  {Math.round(engine.score * 100)}%
                </div>
              </div>
            ))}
          </div>
          <a
            href="#/details"
            className="block text-center text-xs text-blue-500 mt-3 hover:underline"
          >
            View all engine results →
          </a>
        </div>
      )}
    </div>
  )
}
