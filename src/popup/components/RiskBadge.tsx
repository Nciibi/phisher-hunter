import type { RiskLevel } from '../../shared/types/analysis'
import { getRiskColor, getRiskLabel } from '../../shared/types/analysis'

interface RiskBadgeProps {
  risk: RiskLevel
  score: number
  confidence: number
}

export default function RiskBadge({ risk, score, confidence }: RiskBadgeProps) {
  const color = getRiskColor(risk)
  const label = getRiskLabel(risk)
  const percentage = Math.round(score * 100)

  const riskIcons: Record<RiskLevel, string> = {
    safe: '✓',
    low: '○',
    medium: '!',
    high: '!!',
    critical: '✕'
  }

  return (
    <div className="flex flex-col items-center py-4 px-6 bg-[var(--bg-secondary)] rounded-xl">
      <div
        className="w-16 h-16 rounded-full flex items-center justify-center mb-3 text-2xl font-bold"
        style={{
          background: `conic-gradient(${color} 0% ${percentage}%, var(--bg-tertiary) ${percentage}% 100%)`,
          color: '#fff',
          textShadow: '0 1px 2px rgba(0,0,0,0.3)'
        }}
      >
        {riskIcons[risk]}
      </div>
      <div className="text-lg font-bold" style={{ color }}>
        {label}
      </div>
      <div className="flex gap-4 mt-2">
        <div className="text-center">
          <div className="text-xs text-[var(--text-tertiary)]">Risk Score</div>
          <div className="text-sm font-semibold text-[var(--text-primary)]">{percentage}%</div>
        </div>
        <div className="text-center">
          <div className="text-xs text-[var(--text-tertiary)]">Confidence</div>
          <div className="text-sm font-semibold text-[var(--text-primary)]">{Math.round(confidence * 100)}%</div>
        </div>
      </div>
    </div>
  )
}
