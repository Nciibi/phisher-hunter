# Phisher Hunter 🎯

**Next-generation phishing detection through novel, never-before-seen techniques.**

Not another URL blacklist. Not another domain checker. Phisher Hunter uses 9 proprietary detection engines that think like attackers to catch phishing that everything else misses.

## Novel Detection Techniques

### 🎣 Credential Canary
Invisible honeypot credential fields deployed into every page. Phishing scripts that auto-fill or scrape form fields interact with these decoys, revealing their malicious intent. Legitimate users never see them. **Catches credential harvesters in the act.**

### 👁️ Visual Brand Fingerprinting
Computes a structural hash of the page DOM and compares it against known legitimate brand page fingerprints. Phishing sites that copy HTML structure of real brands get caught even on custom domains. **Layout matching, not domain matching.**

### 📊 URL Entropy Analysis
Calculates Shannon entropy of each URL component. Phishing URLs have high-entropy (random-looking) subdomains, paths, and parameters. Also detects base64 segments, UUIDs, and randomly-generated strings. **Statistics don't lie.**

### 🎨 CSS Deception Analysis
Scans stylesheets for visual deception: full-viewport overlays, clickjacking iframes, fake browser chrome, hidden elements, and brand color reproduction. **Catches what the eye can't see.**

### 🧠 Phishing Language Pattern Matrix
N-gram frequency analysis against 5 categories of phishing language: urgency, authority impersonation, threats, rewards, and credential framing. **Reads between the lines.**

### ⏱️ Script Behavior Time-series
Temporal analysis of JavaScript patterns detecting time-delayed phishkits, form action mutations, data exfiltration, and event listener stacking. **Catches delayed-execution attacks.**

### 🔐 Certificate Anomaly Detection
Beyond basic validation: tracks certificate age, issuance velocity, CA clustering, and subject/domain mismatches. **Phishing certs have tells.**

### 🔗 Temporal Domain Clustering
Clusters domains by registration patterns to detect coordinated phishing campaigns. Edit-distance matching across observed domains. **Connects the dots between attacks.**

### 🪤 Interactive Honeypot Detection
Detects hidden interactive elements used by phishers to fingerprint researchers and evade automated analysis. **Turns their tricks against them.**

## Why This Is Different

| Feature | Traditional Extensions | Phisher Hunter |
|---------|----------------------|----------------|
| Detection Method | URL blacklists | Behavioral + statistical analysis |
| Zero-day Protection | Limited | High (anomaly-based) |
| Offline Capability | Minimal | Full (all engines local) |
| Evasion Resistance | Low | High (canary + honeypot-aware) |
| Phishkit Detection | No | Yes (DOM fingerprinting) |
| Campaign Tracking | No | Yes (temporal clustering) |
| Language Analysis | No | Yes (pattern matrix) |

## Architecture

```
src/
├── background/
│   ├── engines/          # 9 novel detection engines
│   │   ├── credential-canary.ts
│   │   ├── visual-fingerprint.ts
│   │   ├── url-entropy.ts
│   │   ├── css-deception.ts
│   │   ├── language-matrix.ts
│   │   ├── script-timeseries.ts
│   │   ├── certificate-anomaly.ts
│   │   ├── temporal-clustering.ts
│   │   └── interactive-honeypot.ts
│   ├── risk/             # Weighted scoring engine
│   ├── storage/          # Cache & settings
│   └── api/              # Rate limiter & retry
├── content/              # DOM scanner & canary injector
├── popup/                # React + Tailwind UI
├── warning/              # Full-page interstitial
└── shared/               # Types, constants, utils
```

## Quick Start

```bash
npm install
npm run build          # Build to dist/
npm run test           # 73 tests across 5 test files
npm run test:coverage  # With coverage
npm run lint           # ESLint
npm run typecheck      # TypeScript
```

Load `dist/` unpacked in `chrome://extensions` (Developer mode).

## Privacy

- Zero browsing history collection
- Zero tracking or telemetry
- All analysis runs locally
- No external API calls for detection
- Minimal permissions (storage, alarms, tabs, webNavigation, scripting)

## Tech Stack

Manifest V3 · TypeScript · React 19 · Tailwind CSS 4 · Vite 8 · Vitest

## License

MIT
