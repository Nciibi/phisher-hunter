import { useCurrentTab } from '../hooks/useCurrentTab'
import { useRiskAnalysis } from '../hooks/useRiskAnalysis'
import Header from '../components/Header'
import RiskBadge from '../components/RiskBadge'
import ThreatDetails from '../components/ThreatDetails'
import ActionButtons from '../components/ActionButtons'
import DomainInfo from '../components/DomainInfo'
import Footer from '../components/Footer'

export default function MainPage() {
  const tab = useCurrentTab()
  const { analysis, loading, error, refresh } = useRiskAnalysis(tab?.url)

  if (!tab) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] p-8 text-center">
        <div className="text-6xl mb-4">🛡️</div>
        <h2 className="text-xl font-semibold mb-2">Phisher Hunter</h2>
        <p className="text-secondary text-sm">
          Open a webpage to see phishing protection analysis.
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col min-h-[500px]">
      <Header domain={tab.url} favIcon={tab.favIconUrl} />

      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : error ? (
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="text-center">
            <div className="text-4xl mb-3">⚠️</div>
            <p className="text-sm text-secondary">Analysis unavailable</p>
            <button onClick={refresh} className="mt-3 text-sm text-blue-500 hover:underline">
              Retry
            </button>
          </div>
        </div>
      ) : analysis ? (
        <>
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
            <RiskBadge
              risk={analysis.risk}
              score={analysis.riskScore}
              confidence={analysis.confidence}
            />
            <ThreatDetails analysis={analysis} />
            <DomainInfo domain={analysis.domain} />
            <ActionButtons
              url={tab.url}
              domain={analysis.domain}
              isWhitelisted={analysis.isWhitelisted}
              isBlacklisted={analysis.isBlacklisted}
              onRefresh={refresh}
            />
          </div>
          <Footer analysis={analysis} />
        </>
      ) : null}
    </div>
  )
}
