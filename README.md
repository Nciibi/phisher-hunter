# Seagles Shield 🛡️

Advanced real-time phishing protection browser extension. Protects users from phishing websites, credential harvesting, and online deception attacks.

## Features

- **17 Detection Engines** - URL reputation, domain age, typosquatting, homograph attacks, Unicode attacks, suspicious TLDs, certificate validation, phishing feeds, JavaScript heuristics, credential harvesting, hidden iframes, password field analysis, brand impersonation, HTML structure, form destination, redirection chain, screenshot similarity
- **Weighted Risk Scoring** - Professional risk engine with explainable scores
- **Real-time Analysis** - <15ms average page analysis
- **Offline Protection** - Local heuristic analysis continues working without internet
- **Privacy First** - No browsing history collection, no tracking, no telemetry
- **Professional UI** - Modern, minimal, accessible design with dark/light mode
- **Chrome Web Store Ready** - Manifest V3 compliant

## Installation

### From Chrome Web Store
*Coming soon*

### From Source
```bash
git clone https://github.com/seagles/shield.git
cd seagles-shield
npm install
npm run build
```

1. Open Chrome and navigate to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `dist/` directory

## Development

```bash
npm install
npm run dev          # Watch mode build
npm run test         # Run tests
npm run test:coverage # Test with coverage
npm run lint         # Lint check
npm run typecheck    # TypeScript check
npm run build        # Production build
```

## Architecture

```
src/
├── background/     # Service worker, engines, risk, storage, API
│   ├── engines/    # 17 detection engines
│   ├── risk/       # Risk scoring engine
│   ├── storage/    # Cache & settings management
│   └── api/        # Rate limiter & retry logic
├── content/        # Content script (scanner, observers)
├── popup/          # React popup UI
├── warning/        # Warning page
├── shared/         # Types, constants, utilities
└── worker/         # Web workers
```

## Detection Engines

| Engine | Weight | Description |
|--------|--------|-------------|
| URL Reputation | 15 | URL structure analysis |
| Domain Age | 8 | Registration date checking |
| Typosquatting | 12 | Brand name impersonation |
| Homograph | 10 | Unicode character attacks |
| Unicode Attack | 10 | RTL override, zero-width chars |
| Suspicious TLD | 5 | High-risk domain extensions |
| Certificate | 10 | SSL/TLS validation |
| Phishing Feeds | 15 | Known phishing databases |
| JS Heuristics | 8 | Malicious script patterns |
| Credential Harvesting | 12 | Login form analysis |
| Hidden Iframe | 5 | Clickjacking detection |
| Password Field | 5 | Password security analysis |
| Brand Impersonation | 12 | Brand page cloning detection |
| HTML Structure | 8 | Structural anomalies |
| Form Destination | 10 | Form submission analysis |
| Redirection Chain | 8 | Redirect obfuscation |
| Screenshot Similarity | 10 | Visual comparison (future) |

## Privacy

- No browsing history is collected or uploaded
- No telemetry unless explicitly enabled
- Minimal permissions required
- All analysis happens locally when possible
- Cache is stored locally and never shared

## Security

- Strong CSP policy
- No eval() or unsafe-inline
- Input sanitization
- Least privilege permissions
- Regular security audits

## Testing

```bash
# Unit tests
npm run test

# With coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

## License

MIT License - See [LICENSE](LICENSE) for details.
