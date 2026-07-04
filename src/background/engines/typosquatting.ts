import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'
import { detectTyposquatting } from '../../shared/utils/domain'

export class TyposquattingEngine extends BaseEngine {
  id = 'typosquatting'
  name = 'Typosquatting Detection'
  description = 'Detects typosquatting attacks targeting known brands'
  version = '1.0.0'
  weight = 12

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.85

    const hostname = context.hostname.toLowerCase().replace(/^www\./, '')
    details.hostname = hostname

    const typosquatResult = detectTyposquatting(hostname)

    if (typosquatResult.isSuspicious) {
      switch (typosquatResult.type) {
        case 'homograph':
          score = 0.9
          reasons.push(
            `Homograph attack detected: "${hostname}" visually impersonates "${typosquatResult.matchedDomain}"`
          )
          break
        case 'tld_substitution':
          score = 0.85
          reasons.push(
            `TLD substitution detected: "${hostname}" uses a different TLD to impersonate "${typosquatResult.matchedDomain}"`
          )
          break
        case 'subdomain_trick':
          score = 0.8
          reasons.push(
            `Subdomain trick detected: "${hostname}" uses brand name as subdomain to deceive`
          )
          break
        case 'typo':
          score = 0.7
          reasons.push(
            `Typo-squatting detected: "${hostname}" is one character off from "${typosquatResult.matchedDomain}"`
          )
          break
        case 'misspelling':
          score = 0.6
          reasons.push(
            `Possible misspelling: "${hostname}" closely resembles "${typosquatResult.matchedDomain}"`
          )
          break
        case 'extra_domain':
          score = 0.65
          reasons.push(
            `Domain contains embedded brand name: "${hostname}" includes "${typosquatResult.matchedDomain?.split('.')[0]}"`
          )
          break
        default:
          score = 0.5
          reasons.push(
            `Suspicious domain: "${hostname}" resembles known brand "${typosquatResult.matchedBrand}"`
          )
      }

      if (typosquatResult.matchedBrand) {
        details.matchedBrand = typosquatResult.matchedBrand
        details.impersonatedDomain = typosquatResult.matchedDomain
        details.squatType = typosquatResult.type
        reasons.push(
          `Target brand identified: "${typosquatResult.matchedBrand}"`
        )
      }
    } else {
      reasons.push('No typosquatting patterns detected')
    }

    const recommendation = score > 0.5
      ? 'This domain appears to be impersonating a known brand. Do not enter any credentials.'
      : 'No brand impersonation detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
