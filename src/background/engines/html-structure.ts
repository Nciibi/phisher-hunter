import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

export class HtmlStructureEngine extends BaseEngine {
  id = 'html-structure'
  name = 'HTML Structure Analysis'
  description = 'Analyzes HTML structure for phishing patterns and anomalies'
  version = '1.0.0'
  weight = 8

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    let confidence = 0.6

    const html = context.html || ''
    details.htmlLength = html.length

    if (!html) {
      reasons.push('No HTML content available for analysis')
      confidence = 0.2
      return this.createResult(score, confidence, reasons, 'No HTML to analyze.', details)
    }

    const title = context.documentProps?.title || ''
    details.pageTitle = title

    if (!title) {
      score += 0.15
      reasons.push('Page has no title tag - unusual for legitimate websites')
    }

    const faviconMatch = html.match(/<link[^>]*rel=["']?icon["']?[^>]*>/i)
    const faviconShortcutMatch = html.match(/<link[^>]*rel=["']?shortcut icon["']?[^>]*>/i)
    if (!faviconMatch && !faviconShortcutMatch) {
      score += 0.05
      reasons.push('No favicon detected - uncommon for legitimate sites')
    }

    const metaDescriptionMatch = html.match(/<meta[^>]*name=["']?description["']?[^>]*>/i)
    if (!metaDescriptionMatch) {
      score += 0.05
    }

    const imageCount = (html.match(/<img[^>]*>/gi) || []).length
    details.imageCount = imageCount

    const linkCount = (html.match(/<a[^>]*>/gi) || []).length
    details.linkCount = linkCount

    if (imageCount > 0 && linkCount === 0) {
      score += 0.15
      reasons.push('Page has images but no links - unusual for legitimate content')
    }

    const loginFormCount = (html.match(/<input[^>]*type=["']?password["']?[^>]*>/gi) || []).length
    const totalFormCount = (html.match(/<form[^>]*>/gi) || []).length
    details.loginFormCount = loginFormCount
    details.totalFormCount = totalFormCount

    if (loginFormCount > 0 && totalFormCount === 0) {
      score += 0.2
      reasons.push('Password fields detected outside of any form element')
    }

    const doctypeMatch = html.match(/<!DOCTYPE[\s\S]*?>/i)
    if (!doctypeMatch) {
      score += 0.05
      reasons.push('Missing DOCTYPE declaration')
    }

    const bodyTagMatch = html.match(/<body[^>]*>/i)
    if (!bodyTagMatch) {
      score += 0.1
      reasons.push('No body tag detected - incomplete HTML structure')
    }

    const baseTagMatch = html.match(/<base[^>]*href=["']([^"']+)["'][^>]*>/i)
    if (baseTagMatch) {
      const baseHref = baseTagMatch[1]
      const pageDomain = context.hostname
      try {
        const baseDomain = new URL(baseHref).hostname
        if (baseDomain !== pageDomain) {
          score += 0.3
          reasons.push(
            `Base href points to different domain: "${baseDomain}" (page: "${pageDomain}")`
          )
          details.baseHref = baseHref
        }
      } catch {
        score += 0.1
      }
    }

    const metaRefreshMatch = html.match(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*content=["']?\d+;\s*url=([^"'>]+)/i)
    if (metaRefreshMatch) {
      score += 0.2
      const redirectUrl = metaRefreshMatch[1]
      reasons.push('Meta refresh redirect detected - possible redirection to phishing site')
      details.metaRefreshUrl = redirectUrl
    }

    const commentCount = (html.match(/<!--[\s\S]*?-->/g) || []).length
    if (commentCount > 50) {
      score += 0.1
      reasons.push(`Excessive HTML comments (${commentCount}) - may hide content`)
    }

    const formActionEmpty = (html.match(/<form[^>]*action\s*=\s*["']\s*["']/gi) || []).length
    if (formActionEmpty > 0 && loginFormCount > 0) {
      score += 0.15
      reasons.push(`${formActionEmpty} form(s) with empty action attribute`)
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'HTML structure analysis reveals patterns consistent with phishing sites.'
      : score > 0.2
        ? 'Some HTML structure anomalies detected.'
        : 'HTML structure appears normal.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }
}
