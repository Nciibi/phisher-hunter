# Seagles Shield Architecture

## Overview

Seagles Shield is a Manifest V3 Chrome Extension designed for real-time phishing protection. It uses a modular, event-driven architecture with 17 independent detection engines feeding into a weighted risk scoring system.

## Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Background Worker                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   Engine Manager                       │  │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐       │  │
│  │  │ URL  │ │Domain│ │Typo  │ │Homo  │ │Uni.. │  ...   │  │
│  │  │ Rep  │ │ Age  │ │Squat │ │graph │ │code  │        │  │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘       │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    Risk Engine                         │  │
│  │  Weighted scoring → Risk level → Recommendations      │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌──────────────────────┐  ┌────────────────────────────┐  │
│  │   Settings Manager   │  │      Analysis Cache        │  │
│  └──────────────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼
┌─────────────────┐ ┌──────────────┐ ┌──────────────────┐
│  Content Script │ │    Popup     │ │   Warning Page   │
│  Scanner/Obsrv  │ │  React UI    │ │  Full-screen     │
│  DOM Collector  │ │  Analysis    │ │  Interstitial    │
└─────────────────┘ └──────────────┘ └──────────────────┘
```

## Data Flow

1. User navigates to a page
2. Content script collects DOM data (forms, iframes, scripts, links)
3. Message sent to background worker with page context
4. EngineManager runs all enabled detection engines in parallel
5. Each engine produces score (0-1), confidence, reasons
6. RiskEngine computes weighted final score and risk level
7. Result cached and sent back to popup/content script
8. If high/critical risk, warning overlay is displayed

## Module Design

### Background Worker (`src/background/`)
- **Engines**: 17 independent detection engines, each extending `BaseEngine`
- **Risk**: Weighted scoring engine with explainable results
- **Storage**: Settings, cache, whitelist/blacklist management
- **API**: Rate limiter and retry logic for external requests

### Content Script (`src/content/`)
- Collects page data (forms, iframes, scripts, links, headers)
- Monitors DOM mutations for dynamic changes
- Displays warning overlay for high-risk sites

### Popup UI (`src/popup/`)
- React + Tailwind CSS interface
- Hash-based routing (Main, Details, Settings, Whitelist)
- Real-time analysis display with risk badge

### Warning Page (`src/warning/`)
- Full-page interstitial warning
- Detailed risk breakdown
- Options to go back or proceed anyway

## Security Design

### Content Security Policy
```
script-src 'self'; object-src 'self';
```

### Permissions (Least Privilege)
- `storage` - Local settings and cache
- `alarms` - Periodic cache cleanup
- `tabs` - Tab URL access
- `webNavigation` - Navigation event tracking
- `scripting` - Content script injection

### No Data Collection
- No browsing history uploaded
- No telemetry by default
- All analysis done locally
- Cache stored only on device

## Performance Targets

- Page analysis: <15ms average
- Engine execution: <200ms per engine
- Popup load: <200ms
- Content script: <100ms on load
- Memory: <50MB steady state

## Testing Strategy

- **Unit tests**: Vitest for engines, risk, utils
- **Integration tests**: Engine manager flow
- **E2E tests**: Playwright for full extension testing
- **Coverage target**: 95%+
