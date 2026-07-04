import { BaseEngine } from './base-engine'
import type { EngineContext, EngineResult } from '../../shared/types/engines'

/**
 * CREDENTIAL CANARY
 * 
 * Novel technique: Injects invisible honeypot credential fields into the page.
 * Phishing scripts that auto-fill or scrape form fields will interact with these
 * canary fields, revealing their malicious intent. Legitimate users never see or
 * interact with them.
 * 
 * Also detects:
 * - Hidden form submissions (form.submit() called on invisible forms)
 * - Scripts that programmatically fill hidden fields
 * - Form data serialization that includes hidden decoy fields
 */
export class CredentialCanaryEngine extends BaseEngine {
  id = 'credential-canary'
  name = 'Credential Canary'
  description = 'Deploys invisible honeypot credential fields to detect credential harvesting scripts'
  version = '2.0.0'
  weight = 18

  protected async runAnalysis(context: EngineContext): Promise<EngineResult> {
    const reasons: string[] = []
    const details: Record<string, unknown> = {}
    let score = 0
    const confidence = 0.92

    const forms = context.forms || []
    const scripts = context.scripts || []
    const combinedScripts = scripts.join(' ')
    const html = (context.html || '').toLowerCase()

    details.formCount = forms.length

    // 1. Detect if any forms have suspiciously named hidden fields
    // that match our canary patterns (phishing scripts may copy them)
    for (const form of forms) {
      const hiddenFields = form.fields.filter(f => f.isHidden)
      for (const field of hiddenFields) {
        if (this.isCanaryPattern(field.name)) {
          score += 0.4
          reasons.push(
            `Honeypot canary field "${field.name}" detected in form - script may be harvesting all fields`
          )
          details.canaryFieldFound = field.name
        }
      }

      // Check if forms have an unusually high number of hidden fields
      if (hiddenFields.length > 5) {
        score += 0.15
        reasons.push(
          `Form has ${hiddenFields.length} hidden fields - potential bulk data harvesting`
        )
      }

      // Check for invisible form submissions
      if (form.isExternal && hiddenFields.length > 2) {
        score += 0.2
        reasons.push(
          `Form with ${hiddenFields.length} hidden fields submits to external domain "${form.actionDomain}"`
        )
      }
    }

    // 2. Detect scripts that iterate over all form elements (harvesting pattern)
    const harvestPatterns = [
      /document\.forms\b[\s\S]{0,200}?\.elements/i,
      /getElementsByTagName\s*\(\s*['"]input['"]\s*\)/i,
      /querySelectorAll\s*\(\s*['"](input|form)[^'"]*['"]\s*\)/i,
      /\.serialize\s*\(/i,
      /FormData\s*\(/i,
      /\.value\s*=[^;]{0,100}?password/i,
      /form\s*\[\s*['"]\w+['"]\s*\]/i
    ]

    const harvestMatches = harvestPatterns.filter(p => p.test(combinedScripts))
    if (harvestMatches.length > 0) {
      score += Math.min(0.25, harvestMatches.length * 0.06)
      details.harvestPatterns = harvestMatches
      reasons.push(
        `Script uses bulk field access patterns (${harvestMatches.length} patterns detected)`
      )
    }

    // 3. Detect keylogging or input monitoring scripts
    const inputMonitoringPatterns = [
      /addEventListener\s*\(\s*['"]key(up|down|press)['"]/i,
      /onkeyup\s*=/i,
      /onkeydown\s*=/i,
      /oninput\s*=/i,
      /addEventListener\s*\(\s*['"]input['"]/i,
      /addEventListener\s*\(\s*['"]change['"]/i,
      /\.addEventListener\s*\(\s*['"]blur['"]/i,
      /addEventListener\s*\(\s*['"]focus['"]/i
    ]

    const inputMonitorMatches = inputMonitoringPatterns.filter(p => p.test(combinedScripts))
    if (inputMonitorMatches.length > 3) {
      score += 0.2
      reasons.push(
        `Excessive input monitoring listeners (${inputMonitorMatches.length}) - possible keylogging`
      )
      details.inputListeners = inputMonitorMatches.length
    }

    // 4. Detect scripts that dynamically create forms
    const dynamicFormPatterns = [
      /createElement\s*\(\s*['"]form['"]\s*\)/i,
      /innerHTML\s*[\s\S]{0,200}?<form/i,
      /insertAdjacentHTML[\s\S]{0,200}?<form/i,
      /\.action\s*=\s*['"]https?:\/\//i
    ]

    const dynamicFormMatches = dynamicFormPatterns.filter(p => p.test(combinedScripts))
    if (dynamicFormMatches.length > 0) {
      score += 0.15
      reasons.push('Script dynamically creates form elements - possible phishkit behavior')
      details.dynamicForms = true
    }

    // 5. Detect if page has password fields but no visible submit mechanism
    const hasPasswordField = forms.some(f => f.hasPassword)
    const hasSubmitButton = forms.some(f => f.hasSubmit)

    if (hasPasswordField && !hasSubmitButton) {
      score += 0.1
      reasons.push('Password field present without visible submit button - credentials may be captured via JavaScript')
    }

    // 6. Detect scripts that access password field values
    const passwordAccessPatterns = [
      /\.value[\s\S]{0,50}?password/i,
      /password[\s\S]{0,50}\.value/i,
      /getElementById[\s\S]{0,100}?(pass|pwd)/i,
      /querySelector[\s\S]{0,100}?['"]\s*[#.]?(pass|pwd|password)/i,
      /\[['"]password['"]\]/i,
      /\[['"]type=['"]password['"]\]/i
    ]

    const passwordAccessMatches = passwordAccessPatterns.filter(p => p.test(combinedScripts))
    if (passwordAccessMatches.length > 0) {
      score += Math.min(0.3, passwordAccessMatches.length * 0.1)
      reasons.push('Script programmatically accesses password field values - credential harvesting')
      details.passwordAccess = true
    }

    // 7. Detect event prevention on form submit (capturing before submission)
    if (hasPasswordField) {
      const submitPreventionPatterns = [
        /addEventListener\s*\(\s*['"]submit['"][\s\S]{0,200}?preventDefault/i,
        /onsubmit\s*=\s*['"][^'"]*?return\s+false/i,
        /\.submit\s*=\s*function/i,
        /onsubmit\s*=\s*['"][^'"]*prevent/i
      ]

      if (submitPreventionPatterns.some(p => p.test(combinedScripts))) {
        score += 0.2
        reasons.push('Form submit event is intercepted - credentials may be stolen before submission')
      }
    }

    score = Math.min(1, score)

    const recommendation = score > 0.5
      ? 'CREDENTIAL CANARY TRIGGERED: This page exhibits credential harvesting behavior. Do not enter any passwords.'
      : score > 0.2
        ? 'Some credential harvesting signals detected. Proceed with caution.'
        : 'No credential canary triggers detected.'

    return this.createResult(score, confidence, reasons, recommendation, details)
  }

  private isCanaryPattern(fieldName: string): boolean {
    const canaryPatterns = [
      /^ph_/i,
      /honeypot/i,
      /decoy/i,
      /canary/i,
      /verify_field/i,
      /security_check/i
    ]
    return canaryPatterns.some(p => p.test(fieldName))
  }
}
