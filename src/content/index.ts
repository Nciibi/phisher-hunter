import type { EngineContext, FormInfo, IframeInfo, FormFieldInfo } from '../shared/types/engines'
import type { ExtensionMessage, WarningPageData } from '../shared/types/messages'
import { MESSAGE_ACTION_PREFIX, EXTENSION_NAME } from '../shared/constants'

let pageData: Partial<EngineContext> = {}
let warningOverlay: HTMLDivElement | null = null
let isScanning = false

function initialize(): void {
  collectPageData()
  setupObservers()
  setupMessageListener()
  setupNavigationListener()
  sendAnalysisRequest()
}

function collectPageData(): void {
  try {
    pageData.url = window.location.href
    pageData.hostname = window.location.hostname
    pageData.domain = window.location.hostname
    pageData.protocol = window.location.protocol
    pageData.port = window.location.port
    pageData.path = window.location.pathname
    pageData.query = window.location.search
    pageData.fragment = window.location.hash

    pageData.documentProps = {
      title: document.title,
      domain: window.location.hostname,
      lastModified: new Date(document.lastModified).getTime(),
      referrer: document.referrer,
      cookiesEnabled: navigator.cookieEnabled
    }

    pageData.html = document.documentElement?.outerHTML?.slice(0, 100000) || ''
    pageData.forms = collectForms()
    pageData.links = collectLinks()
    pageData.scripts = collectScripts()
    pageData.iframes = collectIframes()
    pageData.headers = collectHeaders()
  } catch {
    // Partial data collection is acceptable
  }
}

function collectForms(): FormInfo[] {
  const forms: FormInfo[] = []
  try {
    const formElements = document.querySelectorAll('form')
    formElements.forEach(form => {
      const fields: FormFieldInfo[] = []
      const inputs = form.querySelectorAll('input, select, textarea')
      inputs.forEach(input => {
        const htmlInput = input as HTMLInputElement
        fields.push({
          type: htmlInput.type || 'text',
          name: htmlInput.name || '',
          id: htmlInput.id || '',
          placeholder: htmlInput.placeholder || '',
          isPassword: htmlInput.type === 'password',
          isHidden: htmlInput.type === 'hidden' ||
            htmlInput.style.display === 'none' ||
            htmlInput.style.visibility === 'hidden' ||
            (htmlInput.offsetWidth === 0 && htmlInput.offsetHeight === 0)
        })
      })

      let actionDomain = ''
      try {
        actionDomain = form.action ? new URL(form.action, window.location.href).hostname : ''
      } catch {
        actionDomain = ''
      }

      forms.push({
        action: form.action || '',
        method: form.method || 'get',
        fields,
        hasPassword: fields.some(f => f.isPassword),
        hasSubmit: fields.some(f => f.type === 'submit'),
        actionDomain,
        isExternal: actionDomain !== '' && actionDomain !== window.location.hostname
      })
    })
  } catch {
    // Form collection failure
  }
  return forms
}

function collectLinks(): string[] {
  try {
    const anchors = document.querySelectorAll('a[href]')
    return Array.from(anchors)
      .map(a => (a as HTMLAnchorElement).href)
      .filter(href => href.startsWith('http'))
      .slice(0, 200)
  } catch {
    return []
  }
}

function collectScripts(): string[] {
  try {
    const scripts = document.querySelectorAll('script')
    return Array.from(scripts)
      .map(s => s.textContent || s.src)
      .filter(Boolean)
      .slice(0, 50)
  } catch {
    return []
  }
}

function collectIframes(): IframeInfo[] {
  const iframes: IframeInfo[] = []
  try {
    const iframeElements = document.querySelectorAll('iframe')
    iframeElements.forEach(iframe => {
      const rect = iframe.getBoundingClientRect()
      const style = window.getComputedStyle(iframe)
      const isHidden =
        iframe.style.display === 'none' ||
        iframe.style.visibility === 'hidden' ||
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        rect.width <= 5 ||
        rect.height <= 5 ||
        rect.x < 0 ||
        rect.y < 0

      let domain = ''
      try {
        domain = iframe.src ? new URL(iframe.src).hostname : ''
      } catch {
        domain = ''
      }

      iframes.push({
        src: iframe.src || '',
        width: String(iframe.width || rect.width),
        height: String(iframe.height || rect.height),
        isHidden,
        domain
      })
    })
  } catch {
    // Iframe collection failure
  }
  return iframes
}

function collectHeaders(): Record<string, string> {
  try {
    const headers: Record<string, string> = {}
    const elements = document.querySelectorAll('meta[http-equiv]')
    elements.forEach(el => {
      const meta = el as HTMLMetaElement
      headers[meta.httpEquiv.toLowerCase()] = meta.content || ''
    })
    return headers
  } catch {
    return {}
  }
}

function setupObservers(): void {
  const observer = new MutationObserver(() => {
    if (!isScanning) {
      isScanning = true
      requestAnimationFrame(() => {
        pageData.forms = collectForms()
        pageData.iframes = collectIframes()
        isScanning = false
      })
    }
  })

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['action', 'method']
  })
}

function setupNavigationListener(): void {
  let lastUrl = window.location.href
  const navigationObserver = new MutationObserver(() => {
    const currentUrl = window.location.href
    if (currentUrl !== lastUrl) {
      lastUrl = currentUrl
      collectPageData()
      sendAnalysisRequest()
    }
  })

  navigationObserver.observe(document, { subtree: true, childList: true })
}

function setupMessageListener(): void {
  chrome.runtime.onMessage.addListener((
    message: ExtensionMessage,
    _sender,
    sendResponse
  ) => {
    if (message.type === 'PHISHER_HUNTER_SHOW_WARNING') {
      const data = message.payload as WarningPageData
      showWarningOverlay(data)
      sendResponse({ success: true })
      return true
    }

    if (message.type === 'SCAN_PAGE') {
      collectPageData()
      sendAnalysisRequest()
      sendResponse({ success: true })
      return true
    }

    return false
  })
}

function sendAnalysisRequest(): void {
  const payload = {
    type: 'ANALYZE_URL' as const,
    payload: {
      url: window.location.href,
      tabId: undefined as number | undefined,
      html: pageData.html,
      forms: JSON.stringify(pageData.forms || []),
      links: pageData.links,
      scripts: pageData.scripts,
      iframes: JSON.stringify(pageData.iframes || []),
      headers: pageData.headers
    },
    requestId: crypto.randomUUID(),
    timestamp: Date.now()
  }

  chrome.runtime.sendMessage(payload).catch(() => {
    // Background may not be ready yet
  })
}

function showWarningOverlay(data: WarningPageData): void {
  if (warningOverlay) return

  warningOverlay = document.createElement('div')
  warningOverlay.id = 'seagles-shield-warning'
  warningOverlay.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    z-index: 2147483647; background: rgba(0,0,0,0.85);
    display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  `

  const risk = data.analysis.risk
  const isCritical = risk === 'critical' || risk === 'high'
  const accentColor = isCritical ? '#ea4335' : '#ff6d01'

  warningOverlay.innerHTML = `
    <div style="background: #1a1a2e; border-radius: 16px; padding: 40px; max-width: 560px; width: 90%; box-shadow: 0 24px 48px rgba(0,0,0,0.4); text-align: center; color: #fff;">
      <div style="font-size: 64px; margin-bottom: 16px;">${isCritical ? '🚫' : '⚠️'}</div>
      <h1 style="font-size: 24px; font-weight: 700; margin: 0 0 8px; color: ${accentColor};">
        ${isCritical ? 'Deceptive Site Ahead' : 'Suspicious Site Detected'}
      </h1>
      <p style="font-size: 14px; color: #9aa0a6; margin: 0 0 24px; line-height: 1.5;">
        ${data.analysis.reasons[0] || 'Seagles Shield detected this site may be a phishing attempt.'}
      </p>
      <div style="background: rgba(234,67,53,0.1); border-radius: 12px; padding: 16px; margin-bottom: 24px; text-align: left;">
        <div style="font-size: 12px; color: #9aa0a6; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Risk Assessment</div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <span style="font-size: 14px; color: #fff;">Threat Level:</span>
          <span style="font-size: 14px; font-weight: 600; color: ${accentColor};">
            ${risk.toUpperCase()}
          </span>
        </div>
        <div style="font-size: 12px; color: #9aa0a6; margin-top: 8px; line-height: 1.5;">
          ${data.analysis.reasons.slice(1, 4).join('<br>')}
        </div>
      </div>
      <div style="display: flex; gap: 12px; justify-content: center;">
        <button id="seagles-go-back" style="flex: 1; padding: 12px 24px; border: none; border-radius: 8px; background: ${accentColor}; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;">
          Go Back (Safe)
        </button>
        <button id="seagles-proceed" style="flex: 1; padding: 12px 24px; border: 1px solid #5f6368; border-radius: 8px; background: transparent; color: #9aa0a6; font-size: 14px; cursor: pointer;">
          Proceed Anyway
        </button>
      </div>
      <div style="margin-top: 16px; font-size: 11px; color: #5f6368;">
        Protected by Seagles Shield &bull; ${data.url.replace(/^https?:\/\//, '').slice(0, 40)}
      </div>
    </div>
  `

  document.body.appendChild(warningOverlay)

  const goBack = warningOverlay.querySelector('#seagles-go-back')
  const proceedBtn = warningOverlay.querySelector('#seagles-proceed')

  goBack?.addEventListener('click', () => {
    window.history.back()
    removeWarning()
  })

  proceedBtn?.addEventListener('click', () => {
    removeWarning()
    chrome.runtime.sendMessage({
      type: 'PROCEED_TO_SITE',
      payload: { url: data.url, timestamp: Date.now() }
    })
  })
}

function removeWarning(): void {
  if (warningOverlay) {
    warningOverlay.remove()
    warningOverlay = null
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initialize)
} else {
  initialize()
}
