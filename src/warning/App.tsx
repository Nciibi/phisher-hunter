import { useState } from 'react'
import type { AnalysisResult, RiskLevel } from '../shared/types/analysis'
import { getRiskColor, getRiskLabel } from '../shared/types/analysis'

const WARNING_CSS = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f1a; color: #fff; }
  .container { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .card { background: #1a1a2e; border-radius: 20px; padding: 48px; max-width: 640px; width: 100%; box-shadow: 0 32px 64px rgba(0,0,0,0.5); }
  .icon { font-size: 72px; text-align: center; margin-bottom: 16px; }
  h1 { font-size: 28px; font-weight: 700; text-align: center; margin-bottom: 8px; }
  .subtitle { font-size: 14px; color: #9aa0a6; text-align: center; margin-bottom: 32px; line-height: 1.6; }
  .risk-meter { background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; margin-bottom: 24px; }
  .risk-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .risk-label { font-size: 12px; color: #9aa0a6; text-transform: uppercase; letter-spacing: 1px; }
  .risk-value { font-size: 18px; font-weight: 700; }
  .risk-bar { height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; margin-bottom: 8px; }
  .risk-fill { height: 100%; border-radius: 3px; transition: width 0.5s ease; }
  .risk-stats { display: flex; gap: 16px; }
  .stat { flex: 1; text-align: center; }
  .stat-value { font-size: 16px; font-weight: 600; }
  .stat-label { font-size: 11px; color: #9aa0a6; margin-top: 2px; }
  .reasons { background: rgba(234,67,53,0.08); border-radius: 12px; padding: 16px; margin-bottom: 24px; }
  .reasons-title { font-size: 12px; color: #ea4335; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: 600; }
  .reason { display: flex; gap: 8px; padding: 4px 0; font-size: 13px; color: #e8eaed; line-height: 1.5; }
  .reason-dot { color: #ea4335; flex-shrink: 0; }
  .actions { display: flex; gap: 12px; }
  .btn { flex: 1; padding: 14px 24px; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
  .btn:hover { opacity: 0.9; }
  .btn-primary { color: #fff; }
  .btn-secondary { background: transparent; border: 1px solid #3c4043; color: #9aa0a6; }
  .btn-secondary:hover { background: rgba(255,255,255,0.05); }
  .url { text-align: center; font-size: 11px; color: #5f6368; margin-top: 20px; word-break: break-all; }
  .engines { background: rgba(255,255,255,0.03); border-radius: 12px; padding: 16px; margin-bottom: 24px; }
  .engine-row { display: flex; align-items: center; gap: 10px; padding: 4px 0; }
  .engine-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .engine-name { font-size: 12px; color: #e8eaed; flex: 1; }
  .engine-score { font-size: 12px; font-weight: 600; }
`

export default function App() {
  const [url, setUrl] = useState('')
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [proceeded, setProceeded] = useState(false)

  useState(() => {
    const params = new URLSearchParams(window.location.search)
    const data = params.get('data')
    if (data) {
      try {
        const parsed = JSON.parse(decodeURIComponent(data))
        setUrl(parsed.url)
        setAnalysis(parsed.analysis)
      } catch {
        // Invalid data
      }
    }
  })

  const isCritical = analysis?.risk === 'critical' || analysis?.risk === 'high'
  const accentColor = analysis ? getRiskColor(analysis.risk) : '#ea4335'
  const riskLabel = analysis ? getRiskLabel(analysis.risk) : 'Unknown'

  const handleGoBack = () => {
    window.history.length > 1 ? window.history.back() : window.close()
  }

  const handleProceed = () => {
    setProceeded(true)
    setTimeout(() => {
      const message = { type: 'PROCEED_TO_SITE', payload: { url, timestamp: Date.now() } }
      chrome.runtime.sendMessage(message)
    }, 100)
  }

  if (proceeded) {
    return (
      <div className="container">
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="icon">⚠️</div>
          <h1 style={{ color: '#fbbc04' }}>Proceeding at Your Own Risk</h1>
          <p className="subtitle">
            Seagles Shield detected this site as potentially dangerous.
            Please be extremely careful not to enter any personal information.
          </p>
          <button className="btn btn-primary" style={{ background: accentColor }} onClick={handleGoBack}>
            Go Back
          </button>
        </div>
      </div>
    )
  }

  return (
    <>
      <style>{WARNING_CSS}</style>
      <div className="container">
        <div className="card">
          <div className="icon">{isCritical ? '🚫' : '⚠️'}</div>
          <h1 style={{ color: accentColor }}>
            {isCritical ? 'Deceptive Site Ahead' : 'Suspicious Site Detected'}
          </h1>
          <p className="subtitle">
            {analysis?.reasons[0] || 'Seagles Shield detected this site may be a phishing attempt designed to steal your personal information.'}
          </p>

          <div className="risk-meter">
            <div className="risk-header">
              <span className="risk-label">Threat Level</span>
              <span className="risk-value" style={{ color: accentColor }}>{riskLabel}</span>
            </div>
            <div className="risk-bar">
              <div className="risk-fill" style={{ width: `${(analysis?.riskScore ?? 0) * 100}%`, background: accentColor }} />
            </div>
            <div className="risk-stats">
              <div className="stat">
                <div className="stat-value" style={{ color: accentColor }}>{(analysis?.riskScore ?? 0) * 100}%</div>
                <div className="stat-label">Risk Score</div>
              </div>
              <div className="stat">
                <div className="stat-value">{analysis ? Math.round(analysis.confidence * 100) : 0}%</div>
                <div className="stat-label">Confidence</div>
              </div>
              <div className="stat">
                <div className="stat-value">{analysis?.engines.length || 0}</div>
                <div className="stat-label">Engines</div>
              </div>
            </div>
          </div>

          {analysis && analysis.reasons.length > 1 && (
            <div className="reasons">
              <div className="reasons-title">Why this site is flagged</div>
              {analysis.reasons.slice(1, 6).map((reason, i) => (
                <div key={i} className="reason">
                  <span className="reason-dot">•</span>
                  <span>{reason}</span>
                </div>
              ))}
            </div>
          )}

          {analysis && analysis.engines.filter(e => e.score > 0.3).length > 0 && (
            <div className="engines">
              <div className="reasons-title">Detection Details</div>
              {analysis.engines
                .filter(e => e.score > 0.3)
                .slice(0, 4)
                .map(engine => (
                  <div key={engine.engineId} className="engine-row">
                    <div className="engine-dot" style={{ background: getRiskColor(engine.risk) }} />
                    <span className="engine-name">{engine.engineName}</span>
                    <span className="engine-score" style={{ color: getRiskColor(engine.risk) }}>
                      {Math.round(engine.score * 100)}%
                    </span>
                  </div>
                ))}
            </div>
          )}

          <div className="actions">
            <button className="btn btn-primary" style={{ background: accentColor }} onClick={handleGoBack}>
              Go Back (Safe)
            </button>
            <button className="btn btn-secondary" onClick={handleProceed}>
              Proceed Anyway
            </button>
          </div>

          <div className="url">
            {url.replace(/^https?:\/\//, '').slice(0, 60)}
          </div>
        </div>
      </div>
    </>
  )
}
