import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

export class HiddenIframeEngine extends BaseEngine {
  id = 'hidden-iframe'
  name = 'Hidden Iframe Detection'
  description = 'Detects hidden iframes used for clickjacking and data exfiltration'
  version = '1.0.0'
  weight = 5

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.8

    const iframes = context.iframes || []
    details.iframeCount = iframes.length

    if (iframes.length === 0) {
      reasons.push('No iframes detected on page')
      return this.createResult(score, confidence, reasons, 'No hidden iframe indicators.', details)
    }

    if (iframes.length > 10) {
      score += 0.2
      reasons.push(`Excessive iframes detected (${iframes.length})`)
    }

    const hiddenIframes = iframes.filter(f => f.isHidden)
    const externalIframes = iframes.filter(f => f.domain !== context.hostname)
    const invisibleIframes = iframes.filter(f => {
      const dims = [f.width, f.height].map(d => parseInt(d))
      return dims.some(d => !isNaN(d) && d <= 5)
    })

    details.hiddenCount = hiddenIframes.length
    details.externalCount = externalIframes.length
    details.transparentCount = invisibleIframes.length

    if (hiddenIframes.length > 0) {
      score += Math.min(0.5, hiddenIframes.length * 0.2)
      reasons.push(
        `${hiddenIframes.length} hidden iframe${hiddenIframes.length > 1 ? 's' : ''} detected`
      )
      for (const iframe of hiddenIframes.slice(0, 3)) {
        reasons.push(
          `Hidden iframe: src="${iframe.src || 'empty'}" (1x1px or display:none)`
        )
      }
    }

    if (externalIframes.length > 0) {
      score += Math.min(0.3, externalIframes.length * 0.1)
      reasons.push(
        `${externalIframes.length} external iframe${externalIframes.length > 1 ? 's' : ''} pointing to different domains`
      )
      for (const iframe of externalIframes.slice(0, 3)) {
        if (iframe.isHidden) {
          score += 0.1
          reasons.push(
            `Suspicious hidden external iframe: "${iframe.src}" - potential data exfiltration`
          )
        }
      }
    }

    if (invisibleIframes.length > 0 && hiddenIframes.length === 0) {
      score += Math.min(0.3, invisibleIframes.length * 0.1)
      reasons.push(
        `${invisibleIframes.length} very small iframe${invisibleIframes.length > 1 ? 's' : ''} detected (likely hidden)`
      )
    }

    const phishingIframeDomains = externalIframes.filter(f => {
      const domain = f.domain
      return domain && (
        domain.includes('phishing') ||
        domain.includes('track') ||
        domain.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
      )
    })
    if (phishingIframeDomains.length > 0) {
      score += 0.3
      reasons.push('Iframes pointing to suspicious domains detected')
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'Hidden iframes detected. These are commonly used for clickjacking and covert data theft.'
      : score > 0.2
        ? 'Some iframe anomalies detected. Review before interacting.'
        : 'No suspicious iframe activity detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
