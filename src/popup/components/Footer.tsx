import type { AnalysisResult } from '../../shared/types/analysis'

interface FooterProps {
  analysis: AnalysisResult
}

export default function Footer({ analysis }: FooterProps) {
  const engineCount = analysis.engines.length
  const activeEngines = analysis.engines.filter(e => !e.error).length
  const threatsDetected = analysis.engines.filter(e => e.score > 0.5).length

  return (
    <div className="px-4 py-3 border-t border-[var(--border)] flex items-center justify-between text-xs text-[var(--text-tertiary)]">
      <div className="flex items-center gap-3">
        <span>{engineCount} engines</span>
        <span>{activeEngines} active</span>
        {threatsDetected > 0 && (
          <span className="text-red-500 font-medium">{threatsDetected} threats</span>
        )}
      </div>
      <div className="flex items-center gap-2">
        <a href="#/details" className="text-blue-500 hover:underline">
          Details
        </a>
        <span>·</span>
        <a href="#/settings" className="text-blue-500 hover:underline">
          Settings
        </a>
      </div>
    </div>
  )
}
