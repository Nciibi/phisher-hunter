# Phisher Hunter — Complete Model Upgrade Plan

**Project:** Phisher Hunter (Chrome MV3 Extension)  
**Goal:** Hybrid heuristic + ML phishing detection with 98%+ accuracy  
**Author:** Seagles Security  
**Date:** July 2026  

---

## Table of Contents

1. [Prologue: Why This Upgrade?](#1-prologue-why-this-upgrade)
2. [Book Overview: What We Are Building](#2-book-overview-what-we-are-building)
3. [Milestone 1: ML Infrastructure & Types](#3-milestone-1-ml-infrastructure--types)
4. [Milestone 2: MLModelEngine Base Class](#4-milestone-2-mlmodeengine-base-class)
5. [Milestone 3: URL ML Engine](#5-milestone-3-url-ml-engine)
6. [Milestone 4: DOM Content ML Engine](#6-milestone-4-dom-content-ml-engine)
7. [Milestone 5: Ensemble Engine](#7-milestone-5-ensemble-engine)
8. [Milestone 6: EngineManager & RiskEngine Integration](#8-milestone-6-enginemanager--riskengine-integration)
9. [Milestone 7: Bloom Filter Threat Intelligence](#9-milestone-7-bloom-filter-threat-intelligence)
10. [Milestone 8: Python Training Pipeline](#10-milestone-8-python-training-pipeline)
11. [Milestone 9: Testing & Quality Assurance](#11-milestone-9-testing--quality-assurance)
12. [Milestone 10: Performance Optimization](#12-milestone-10-performance-optimization)
13. [Appendix A: File Inventory](#13-appendix-a-file-inventory)
14. [Appendix B: Dependency List](#14-appendix-b-dependency-list)
15. [Appendix C: Glossary](#15-appendix-c-glossary)

---

# 1. Prologue: Why This Upgrade?

## The Problem

Phisher Hunter currently uses **9 hand-written detection engines**. Each engine is a set of rules written by developers — like a checklist a detective uses to spot criminals. For example:

> "If the URL has more than 4 subdomains, add 0.15 to the risk score."  
> "If the page contains the word 'urgent', add 0.2 to the risk score."

These rules are **brittle**. Attackers read the same research we do, and they adapt:
- They make URLs with fewer subdomains
- They avoid urgent-sounding language
- They tweak their HTML structure slightly to evade fingerprinting

Every new evasion technique requires a human to write a new rule. This is a game of **whack-a-mole** that scales poorly.

## The Solution: Machine Learning

Instead of writing rules by hand, we train **machine learning models** on thousands of real phishing and legitimate pages. The models learn patterns automatically:

- A **character-level CNN** on URLs learns that "paypa1" is visually similar to "paypal" and flags it
- A **TF-IDF + neural network** on page text learns that the phrase "verify your account immediately" correlates strongly with phishing
- An **ensemble** learns which combination of signals is most predictive

Research shows hybrid systems achieve **98-99% accuracy** versus **70-85%** for rule-only systems. The two approaches complement each other: rules catch what we *know* is bad with 100% precision, ML catches what *looks* suspicious even if no human thought to write a rule for it.

---

# 2. Book Overview: What We Are Building

## Architecture at a Glance

```
User visits a page
        │
        ▼
┌─────────────────────────────────────────────┐
│ Content Script (unchanged)                   │
│ Collects: URL, DOM, forms, links, iframes   │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│ Background Service Worker                    │
│                                              │
│  EngineManager.analyzeAll()                  │
│         │                                    │
│         ├── 9 Heuristic Engines (parallel)   │
│         │   ├── credential-canary            │
│         │   ├── visual-fingerprint           │
│         │   ├── url-entropy                  │
│         │   ├── css-deception                │
│         │   ├── language-matrix              │
│         │   ├── script-timeseries            │
│         │   ├── certificate-anomaly          │
│         │   ├── temporal-clustering          │
│         │   └── interactive-honeypot         │
│         │                                    │
│         ├── 2 ML Engines (parallel) [NEW]    │
│         │   ├── url-ml (character CNN)       │
│         │   └── dom-ml (TF-IDF + NN)         │
│         │                                    │
│         └── EnsembleEngine [NEW]             │
│             └── learned logistic fusion      │
│                                              │
│  RiskEngine.calculateRisk()                  │
│  └── uses ensemble score as primary          │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
              Warning or Safe verdict
```

## What Stays the Same

| Component | Status | Reason |
|-----------|--------|--------|
| 9 existing heuristic engines | ✅ Unchanged | Still valuable — rules catch what we know with certainty |
| Content script (DOM extraction) | ✅ Unchanged | Still collects the same data |
| Settings, whitelist, blacklist | ✅ Unchanged | User-facing features remain identical |
| Popup UI (React) | ✅ Unchanged | Visual design and interaction unchanged |
| Warning overlay | ✅ Unchanged | User sees same warning experience |
| Cache system | ✅ Unchanged | Same LRU cache for analysis results |
| Message passing (Chrome runtime) | ✅ Unchanged | Same protocol between content/background/popup |

## What Changes

| Component | Change | Impact |
|-----------|--------|--------|
| `EngineManager` | Registers 2 new ML engines (total 11), returns ensemble result | Backward compatible — existing code that calls `analyzeAll()` gets more data |
| `RiskEngine` | Accepts ensemble result, uses it as primary score | More accurate risk scoring |
| `EngineContext` | Adds `pageText`, `urlTokenIds`, `enableML` fields | Optional fields, all existing contexts still valid |
| `constants.ts` | Adds ML model paths, ML defaults, keyword categories | Only additive — nothing removed |
| `engines.ts` types | Adds 3 optional fields to `EngineContext` | Non-breaking change |

## What Is Entirely New

| Component | Location | Lines of Code (est.) |
|-----------|----------|---------------------|
| ML types & interfaces | `src/shared/types/models.ts` | ~100 |
| MLModelEngine (abstract) | `src/background/engines/ml/ml-model-engine.ts` | ~250 |
| UrlMLModelEngine | `src/background/engines/ml/url-ml-engine.ts` | ~200 |
| DomMLModelEngine | `src/background/engines/ml/dom-ml-engine.ts` | ~200 |
| TF-IDF Vectorizer (TS) | `src/background/engines/ml/tfidf.ts` | ~100 |
| EnsembleEngine | `src/background/engines/ml/ensemble-engine.ts` | ~150 |
| Bloom Filter | `src/background/threat-intel/bloom-filter.ts` | ~200 |
| Feed Manager | `src/background/threat-intel/feed-manager.ts` | ~150 |
| Python training scripts | `python/` directory | ~800 |
| Test files | `tests/unit/engines/ml/`, `tests/unit/threat-intel/` | ~500 |
| Model files | `src/models/` | ~560KB (binary) |
| **Total new code** | | **~2,650 lines** |

---

# 3. Milestone 1: ML Infrastructure & Types

**Goal:** Define all TypeScript interfaces and types for the ML subsystem. These types ensure type safety across all ML components and document the data contracts.

**Status:** ✅ COMPLETED

## What Was Built

### File: `src/shared/types/models.ts`

This file defines **10 interfaces, 1 type, and 1 error class** that every ML component uses:

| Interface | Purpose | Key Fields |
|-----------|---------|------------|
| `ModelConfig` | Describes a trained ML model (architecture, path, thresholds) | `id`, `path`, `inputShape`, `threshold`, `preferredBackend` |
| `InferenceResult` | Output from a single model inference | `score`, `confidence`, `latencyMs`, `status` |
| `EnsembleConfig` | Learned fusion weights loaded from JSON | `weights`, `bias`, `version`, `accuracy` |
| `EnsembleResult` | Output from the ensemble engine | `score`, `confidence`, `contributions[]`, `mode` |
| `EngineContribution` | One engine's contribution to the final score | `engineId`, `weight`, `contribution`, `contributionPercent` |
| `CharTokenizerConfig` | Character-to-integer mapping for URL model | `charToId`, `maxLength`, `specialTokens` |
| `TfidfConfig` | TF-IDF vocabulary and IDF values | `vocabulary`, `idf`, `maxFeatures`, `norm` |
| `MLSubsystemStatus` | Diagnostics: which models are loaded, memory | `tfjsLoaded`, `models[]`, `ensembleMode` |
| `ModelStatus` | Per-model runtime status | `loaded`, `totalInferences`, `averageLatencyMs` |

### Design Decisions

1. **Separation of concerns:** Model config is separate from inference result. The config describes *what the model is*; the result describes *what it predicted*.

2. **Flexible details:** `InferenceResult.details` is `Record<string, unknown>` — ML-specific attribution data (like top contributing words) can be passed through without requiring every engine to produce the same shape.

3. **Error type:** `MLModelError` includes a `code` field (`LOAD_FAILED`, `INFERENCE_FAILED`, `TIMEOUT`, `OOM`, `BACKEND_UNAVAILABLE`) so error handling logic can branch on the type of failure.

4. **Ensemble mode tracking:** `EnsembleResult.mode` tracks whether learned weights or static fallback was used — critical for debugging and for the user settings page.

### File: `src/shared/constants.ts` (updated)

Added constants for ML subsystem:

- `ML_MODEL_PATHS` — canonical paths to model files in the extension bundle
- `ML_DEFAULTS` — sensible defaults (max URL length 200, vocab size 5000, etc.)
- `SUSPICIOUS_TLDS_ML` — TLDs that the ML engine checks as attribution signals
- `KNOWN_URL_SHORTENERS` — common shortener domains to flag
- `PHISHING_KEYWORD_CATEGORIES` — categorized phishing words (urgency, credential, threat, reward, brand)

### File: `src/shared/types/engines.ts` (updated)

Added 3 optional fields to `EngineContext`:

- `pageText?: string` — pre-cleaned visible page text (avoids re-parsing HTML in the ML engine)
- `urlTokenIds?: Uint32Array` — pre-tokenized URL character IDs (avoids re-tokenizing)
- `enableML?: boolean` — flag to disable ML engines (e.g., on low-end devices)

These are **optional** — all existing code that constructs `EngineContext` remains valid.

---

# 4. Milestone 2: MLModelEngine Base Class

**Goal:** Create an abstract base class that all ML engines extend. Encapsulate TF.js lifecycle (initialization, model loading, inference, timeout, fallback) so subclasses only need to implement `preprocess()` and `runMLInference()`.

**Status:** ✅ COMPLETED

## File: `src/background/engines/ml/ml-model-engine.ts`

### Architecture

```
MLModelEngine (abstract)
  │
  ├── Extends BaseEngine (the existing abstract engine base)
  │     └── So it plugs directly into EngineManager
  │
  ├── Owns:
  │   ├── modelConfig: ModelConfig     ← subclass provides
  │   ├── model: any                   ← TF.js GraphModel (cached)
  │   ├── tfjsInitialized: boolean     ← TF.js backend ready?
  │   └── stats: {...}                 ← diagnostics counters
  │
  ├── Abstract methods (subclass must implement):
  │   ├── preprocess(context)          ← convert EngineContext → model input tensor
  │   └── runMLInference(context)      ← run model.predictAsync(), return score
  │
  └── Concrete methods (inherited):
      ├── runAnalysis(context)         ← orchestrates: init → load → infer → fallback
      ├── initializeTFJS()            ← dynamic import TF.js, set backend
      ├── importTFJS()                ← dynamic import (tree-shakable!)
      ├── loadModel()                 ← fetch model.json from chrome-extension://
      ├── runWithTimeout()            ← Promise.race with timeout
      ├── handleModelError()          ← graceful fallback (score=0, confidence=0)
      ├── buildReasons()              ← convert InferenceResult → reasons[]
      ├── getStatus()                 ← for diagnostics UI
      ├── unloadModel()               ← memory cleanup
      └── clearCache()                ← no-op by default
```

### Key Design Decisions

#### Decision 1: Lazy Loading

TF.js and model weights are **not loaded on extension startup**. They load on the first call to `runAnalysis()`. Why?

- Extensions must start fast (<100ms for service worker)
- TF.js + models adds ~300-500ms loading time
- Users who disable ML engines never pay this cost

The `loadInProgress` flag prevents concurrent load attempts. If two tabs trigger analysis simultaneously, the second caller awaits the first's load.

#### Decision 2: Dynamic Import

```typescript
protected async importTFJS(): Promise<any> {
  const tf = await import('@tensorflow/tfjs-core')
  await import('@tensorflow/tfjs-backend-cpu')
  try { await import('@tensorflow/tfjs-backend-webgl') } catch {}
  const converter = await import('@tensorflow/tfjs-converter')
  return { ...tf, loadGraphModel: converter.loadGraphModel }
}
```

Dynamic imports mean Vite/Rollup can **code-split** TF.js into a separate chunk. The chunk is only fetched when ML runs. This:
- Reduces initial extension bundle size by ~300KB
- Enables tree-shaking (unused TF.js features are dropped)
- Allows graceful fallback if WebGL is unavailable

#### Decision 3: Timeout Protection

```typescript
private async runWithTimeout(context: EngineContext): Promise<InferenceResult> {
  const timeoutMs = PERFORMANCE_BUDGETS.MAX_ENGINE_TIME  // 2000ms
  const inferencePromise = this.runMLInference(context)
  const timeoutPromise = new Promise<InferenceResult>((_, reject) => {
    setTimeout(() => reject(new Error('Inference timed out')), timeoutMs)
  })
  return Promise.race([inferencePromise, timeoutPromise])
}
```

If ML inference hangs (e.g., WebGL deadlock, memory pressure), the timeout ensures the extension never blocks. The fallback score (0) is returned.

#### Decision 4: Backend Fallback Chain

```typescript
for (const backend of ['webgl', 'cpu']) {
  try { await tf.setBackend(backend); await tf.ready(); break }
  catch { continue }
}
```

WebGL is 3-10x faster than CPU for neural network inference. We try it first. If unavailable (headless browser, old hardware, WebGL disabled), we silently fall back to CPU. This is transparent to subclass code.

#### Decision 5: Model Pre-warming

```typescript
const dummyInput = tf.zeros(this.modelConfig.inputShape)
await this.model.predictAsync(dummyInput)
dummyInput.dispose()
```

After loading, we run one dummy inference. This forces TF.js to compile the graph and allocate memory. The **first real inference** is then fast instead of paying compilation cost.

### Lifecycle States

```
STATE: UNINITIALIZED
  │
  ├── initializeTFJS() → success
  │     │
  │     ▼
  STATE: TFJS_READY
  │     │
  │     ├── loadModel() → success
  │     │     │
  │     │     ▼
  │     STATE: MODEL_LOADED
  │     │     │
  │     │     ├── runMLInference() → success → return result
  │     │     ├── runMLInference() → error → STATE: TFJS_READY (retry load)
  │     │     └── unloadModel() → STATE: TFJS_READY
  │     │
  │     └── loadModel() → failure → STATE: TFJS_READY (retry next call)
  │
  └── initializeTFJS() → failure
        │
        ▼
  STATE: FALLBACK (permanent for this session, always return score=0)
```

### Fallback Contract

If ANY error occurs in the ML pipeline, the engine returns:

```typescript
{
  engineId: 'url-ml',
  score: 0,
  confidence: 0,
  risk: 'safe',
  reasons: ['ML model unavailable: <error>. Using safe default.'],
  recommendation: 'ML analysis unavailable due to model error'
}
```

The extension **never crashes** because of an ML failure. The `BaseEngine.analyze()` method (inherited) catches all errors from `runAnalysis()` and wraps them in a safe result.

---

# 5. Milestone 3: URL ML Engine

**Goal:** Run a character-level Convolutional Neural Network on the page URL to detect phishing patterns. This is our primary ML-based signal — it catches subtle URL manipulations that rule-based systems miss.

**Status:** ✅ COMPLETED

## File: `src/background/engines/ml/url-ml-engine.ts`

### How URL Tokenization Works

The model cannot read raw URLs. We must convert characters to numbers:

```
Raw URL:  https://secure-paypa1.com/login?token=abc123

Step 1: Normalize
  → "secure-paypa1.com/login?token=abc123"
     (lowercase, strip protocol, strip www)

Step 2: Tokenize (character → integer ID)
  s→19  e→5  c→3  u→21  r→18  e→5  -→62  p→16  a→1
  y→25  p→16  a→1  1→27  .→63  c→3  o→15  m→13  /→64
  l→12  o→15  g→7  i→9  n→14  ?→65  t→20  o→15  k→11
  e→5  n→14  =→66  a→1  b→2  c→3  1→27  2→28  3→29

Step 3: Pad to 200 with zeros
  [19, 5, 3, 21, 18, 5, 62, 16, 1, 25, 16, 1, 27, 63, ... 0, 0, 0]
```

The tokenizer maps 57 standard URL characters (a-z, 0-9, `.-_/?=&%~:@!$'()*+,;#`) to IDs 1-57. ID 0 = padding, ID 58 = unknown character.

### How Inference Works

```typescript
// 1. Preprocess URL → Uint32Array(200)
const inputTensor = await this.preprocess(context)

// 2. Create TF.js tensor
const tf = await this.importTFJS()
const input = tf.tensor(inputTensor, [1, 200], 'int32')

// 3. Run model
const output = await this.model.predictAsync(input)
const score = output.dataSync()[0]  // e.g., 0.973

// 4. Confidence = distance from decision boundary
const confidence = Math.min(1, Math.abs(score - 0.5) * 2)
// score=0.973 → confidence=0.946

// 5. Extract attributions for explainability
const details = this.extractAttributions(context, score)
```

### Attribution Extraction

Since we cannot compute true saliency maps (gradient computation is too expensive for browser inference), we use a **heuristic attribution** system that checks known phishing indicators in the URL:

| Check | Condition | Attribution Message |
|-------|-----------|-------------------|
| Digits in domain | `>2` digits | "Domain contains N digits — possible brand impersonation" |
| Suspicious TLD | `.tk, .ml, .ga, .xyz, .top, ...` | "Suspicious TLD: .xyz" |
| Subdomain count | `>3` subdomains | "Unusual number of subdomains (4)" |
| URL shortener | Matches `bit.ly, tinyurl, t.co, ...` | "URL shortener detected — common in phishing" |
| IP address domain | Regex match `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | "IP address used instead of domain name" |
| Double slashes in path | `//` pattern | "Multiple consecutive slashes — URL manipulation" |

These attributions appear in the `EngineResult.reasons[]` array, making the ML prediction explainable to users.

### Model Architecture (for reference — trained in Python, runs in TF.js)

```
Input: 200 integer character IDs
       │
       ▼
Embedding(128)
  Maps each character to a 128-dim vector
  Similar characters get similar vectors (learned)
       │
       ▼
Conv1D(256, kernel=3, ReLU)     Conv1D(256, kernel=5, ReLU)
  Detects character trigrams        Detects character pentagrams
       │                                │
       ▼                                ▼
GlobalMaxPool1D                   GlobalMaxPool1D
  Takes max activation per filter     Same
       │                                │
       └────────────┬──────────────────┘
                    ▼
           Concatenate (512 features)
                    │
                    ▼
           Dense(128, ReLU)
           Dropout(0.5)
                    │
                    ▼
           Dense(1, Sigmoid)
           Output: 0.0 (legit) – 1.0 (phishing)
```

### Engine Registration

```typescript
id = 'url-ml'
name = 'URL ML Model'
weight = 20  // Highest weight — this is our best general detector
modelConfig.path = 'models/url-cnn/model.json'
```

---

# 6. Milestone 4: DOM Content ML Engine

**Goal:** Analyze the visible text content of a page using TF-IDF vectorization followed by a dense neural network. Catches social engineering language patterns that the hand-crafted LanguageMatrixEngine misses.

**Status:** ✅ COMPLETED

## Files

- `src/background/engines/ml/dom-ml-engine.ts` — the engine itself
- `src/background/engines/ml/tfidf.ts` — TypeScript TF-IDF implementation

### Why TF-IDF + Dense Net Instead of a Transformer?

| Approach | Model Size | Speed | Accuracy | Decision |
|----------|-----------|-------|----------|----------|
| TF-IDF + Dense (chosen) | ~250KB | <5ms | 90-93% | ✅ Best fit for MV3 |
| DistilBERT | ~250MB | ~500ms | 96-98% | ❌ Too large/slow |
| BiLSTM + Attention | ~5MB | ~100ms | 94-96% | ❌ Too heavy for v1 |
| XGBoost via ONNX | ~500KB | <10ms | 91-94% | 👍 Good alternative for v2 |

The TF-IDF approach is **tiny, fast, and good enough**. The vocabulary (5000 words) fits in ~50KB JSON. The neural network is just two dense layers. Total: ~250KB and <5ms inference.

**Future upgrade path:** Replace with DistilBERT via ONNX runtime — the engine interface (`runMLInference`) doesn't change.

### How Text Extraction Works

```typescript
Input HTML:
  <html><body><h1>Sign In</h1><p>Verify your account</p>
  <script>malicious code</script></body></html>

Step 1: Strip <script>, <style>, <svg> blocks
  → "<html><body><h1>Sign In</h1><p>Verify your account</p></body></html>"

Step 2: Strip all HTML tags
  → "Sign In Verify your account"

Step 3: Decode HTML entities (&amp; → &, etc.)
  → "Sign In Verify your account"

Step 4: Lowercase, clean special chars
  → "sign in verify your account"

Step 5: Limit to 10,000 characters
  → "sign in verify your account"
```

### How TF-IDF Vectorization Works (TypeScript)

The `TfidfVectorizer` class implements scikit-learn's TF-IDF algorithm in pure TypeScript:

```typescript
// 1. Tokenize into words
tokens = ["sign", "in", "verify", "your", "account"]

// 2. Compute term frequency (TF)
tf = { sign: 1/5, in: 1/5, verify: 1/5, your: 1/5, account: 1/5 }

// 3. For each token in vocabulary:
//    Look up IDF value, compute TF-IDF = tf × idf
//    "verify" has high IDF (rare in legitimate pages) → high TF-IDF value
//    "your" has low IDF (common everywhere) → low TF-IDF value

// 4. L2-normalize the vector (same as scikit-learn default)
vector[i] /= sqrt(sum(vector[j]^2 for all j))

// Result: Float32Array(5000) — sparse, mostly zeros
```

The TF-IDF config (vocabulary + IDF values) is exported from Python training and bundled as JSON. The vocabulary maps words like "verify" → index 143, "account" → index 289, etc.

### Key Phrase Extraction

After inference, the engine extracts human-readable phishing indicators:

```typescript
const urgencyWords = ['urgent', 'immediately', 'suspended', 'limited', ...]
const credentialWords = ['verify', 'password', 'sign in', 'credentials', ...]
const brandWords = ['paypal', 'google', 'microsoft', 'apple', ...]

// Check if these words appear in the page text
for (const word of urgencyWords) {
  if (text.includes(word)) indicators.push(`Urgency language: "${word}"`)
}
for (const word of credentialWords) {
  if (text.includes(word)) indicators.push(`Credential harvesting: "${word}"`)
}
if (brandWords.some(w => topTfidfWords.includes(w))) {
  indicators.push(`Brand reference detected: "${word}"`)
}
```

### Engine Registration

```typescript
id = 'dom-ml'
name = 'DOM Content ML'
weight = 18  // Second highest — page text is very discriminative
modelConfig.path = 'models/dom-classifier/model.json'
modelConfig.preferredBackend = 'cpu'  // Small model, CPU is fine
```

---

# 7. Milestone 5: Ensemble Engine

**Goal:** Replace the hardcoded static weights in `RiskEngine` with **learned weights** from a trained logistic regression model. The ensemble combines all 11 engines into a single optimal risk score.

**Status:** ✅ COMPLETED

## File: `src/background/engines/ml/ensemble-engine.ts`

### Why Learned Weights Matter

Currently, each engine has a fixed weight:

```typescript
// Current static weights (hand-picked, never change):
'credential-canary': 18,   // Always 18%, regardless of page
'visual-fingerprint': 15,  // Always 15%, regardless of page
'url-entropy': 12,         // Always 12%, regardless of page
```

But the optimal weight **depends on the page**:
- On a bank phishing page: visual-fingerprint (+ML engines) should dominate
- On a credential harvester: credential-canary should dominate
- On a generic spam page: url-ml and dom-ml should dominate

A trained **logistic regression** learns the optimal fixed weights for the entire population, which outperforms hand-picked weights by 2-5% absolute accuracy. Future work could extend this to **per-page-type dynamic weights**.

### How the Ensemble Computes the Score

```typescript
logit = bias + Σ(weight_i × score_i)
score = sigmoid(logit) = 1 / (1 + e^(-logit))
```

Example with 3 engines:

```
url-ml score = 0.22 × 0.97 = 0.2134
credential-canary score = 0.18 × 0.30 = 0.0540
dom-ml score = 0.16 × 0.85 = 0.1360
bias = -0.50

logit = -0.50 + 0.2134 + 0.0540 + 0.1360 = -0.0966
score = 1 / (1 + e^(0.0966)) = 0.476
```

The sigmoid function squashes any real number to [0, 1], producing a valid probability.

### Contribution Percentages

Each engine's contribution is expressed as a percentage of the total positive (or negative) influence:

```typescript
totalPositive = sum(max(0, contribution_i))
for each engine: contributionPercent = max(0, contribution) / totalPositive × 100
```

This makes the ensemble **explainable** — we can tell users "the URL ML model contributed 58% of the risk score."

### Confidence Computation

Three factors determine ensemble confidence:

1. **Distance from decision boundary:** `|score - 0.5|` — predictions far from the boundary are more confident
2. **Engine agreement:** If most engines agree (all high or all low), confidence is higher
3. **ML engine participation:** If ML engines are active, we add a 0-10% bonus (ML is more reliable than heuristics)

```typescript
confidence = min(1, boundaryDistance × 1.5 + agreement × 0.3 + mlBonus)
```

### Fallback Weights (Static)

If `weights.json` fails to load (network error, corrupted file, first install), we use static fallback weights:

| Engine | Fallback Weight | Rationale |
|--------|----------------|-----------|
| url-ml | 0.22 | Highest — ML is most general |
| credential-canary | 0.18 | 100% precision on credential harvesters |
| dom-ml | 0.16 | Second ML — text patterns are strong signals |
| visual-fingerprint | 0.12 | Good for brand impersonation |
| language-matrix | 0.10 | Partially overlaps with dom-ml |
| url-entropy | 0.08 | Narrow but useful signal |
| temporal-clustering | 0.05 | Only active during campaigns |
| css-deception | 0.04 | Hidden element detection |
| script-timeseries | 0.03 | Dynamic behavior (rarely triggers) |
| certificate-anomaly | 0.02 | Many legit sites have cert issues |
| interactive-honeypot | 0.02 | Narrow scope |

---

# 8. Milestone 6: EngineManager & RiskEngine Integration

**Goal:** Wire the new ML engines and ensemble into the existing detection pipeline. Update `EngineManager`, `RiskEngine`, and `background/index.ts` so the full 11-engine + ensemble flow works end-to-end.

**Status:** Partially Complete (EngineManager + types done; RiskEngine + background pending)

## EngineManager Changes

### File: `src/background/engines/index.ts`

#### Before (Old):

```typescript
class EngineManager {
  private engines: Map<string, DetectionEngine>
  private engineOrder: string[]

  async analyzeAll(context): Promise<EngineResult[]> {
    // Run 9 engines in parallel
    // Return array of EngineResult
  }
}
```

#### After (New):

```typescript
class EngineManager {
  private engines: Map<string, DetectionEngine>  // Now 11 entries
  private engineOrder: string[]                    // 11 engine IDs
  private ensemble: EnsembleEngine                  // NEW: fusion engine

  async analyzeAll(context): Promise<{
    engineResults: EngineResult[]   // 11 results
    ensembleResult: EnsembleResult  // NEW: fused score
  }> {
    // 1. Run 11 engines in parallel (9 heuristic + 2 ML)
    // 2. Compute ensemble from results
    // 3. Return both
  }

  // NEW methods:
  getMLStatus(): MLSubsystemStatus
  getEnsembleStatus(): { mode, version }
}
```

## RiskEngine Changes (Pending)

The `RiskEngine.calculateRisk()` needs a new parameter:

```typescript
// Current signature:
calculateRisk(url, domain, engineResults, context): AnalysisResult

// New signature:
calculateRisk(url, domain, engineResults, ensembleResult, context): AnalysisResult
```

Changes inside:
1. If `ensembleResult.confidence >= 0.3`: use `ensembleResult.score` as `riskScore`
2. If `ensembleResult.confidence < 0.3`: fall back to static weighted scoring (existing logic)
3. Include `ensembleResult.contributions` in the returned `AnalysisResult` for explainability

## Background Entry Changes (Pending)

The `performAnalysis()` function in `src/background/index.ts`:

```typescript
// Before:
const engineResults = await engineManager.analyzeAll(context)
const result = riskEngine.calculateRisk(url, domain, engineResults, context)

// After:
const { engineResults, ensembleResult } = await engineManager.analyzeAll(context)
const result = riskEngine.calculateRisk(url, domain, engineResults, ensembleResult, context)
```

New message types to add:
- `GET_ML_STATUS` — returns `MLSubsystemStatus` for settings page
- `RELOAD_ENSEMBLE` — reloads `weights.json` (useful after update)

---

# 9. Milestone 7: Bloom Filter Threat Intelligence

**Goal:** Add a space-efficient, privacy-preserving local database of known phishing domains. The Bloom filter allows fast "is this domain known bad?" lookups without sending URLs to an external server.

**Status:** ✅ COMPLETED (code written)

## Files

- `src/background/threat-intel/bloom-filter.ts` — Bloom filter implementation
- `src/background/threat-intel/feed-manager.ts` — Periodic feed downloader
- `src/background/threat-intel/index.ts` — Exports

## What is a Bloom Filter?

A Bloom filter is a **probabilistic data structure** that answers "have I seen this item before?"

- **Never false negatives:** If a domain IS in the filter, we always detect it
- **Possible false positives:** A domain might APPEAR to be in the filter when it's not (~1.5% of lookups)
- **Very compact:** 400,000 domains in ~1.2MB
- **Very fast:** O(k) lookup where k = number of hash functions (typically 7-15)
- **No privacy risk:** Only stores hashed bits — cannot extract original domains

### How It Works (Visual)

```
Empty filter (all bits = 0):
[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ...]

Add "phishing.com":
  hash1("phishing.com") → position 3
  hash2("phishing.com") → position 7
  hash3("phishing.com") → position 12
  ...
  → Set bits at positions 3, 7, 12, ...

[0 0 0 1 0 0 0 1 0 0 0 0 1 0 0 0 0 0 0 0 ...]

Check "legit.com":
  hash1("legit.com") → position 3   → bit IS set    → maybe!
  hash2("legit.com") → position 15  → bit is NOT set → definitely NOT in filter

Check "phishing.com":
  hash1 → position 3  → bit IS set
  hash2 → position 7  → bit IS set
  hash3 → position 12 → bit IS set
  → All bits set → probably in filter
```

### Hash Functions

We use **double hashing** (Kirsch-Mitzenmacher optimization) to generate k independent hash positions from just 2 hash computations:

```typescript
h1 = fnv1a(item + ":" + seed)        // FNV-1a (fast, good distribution)
h2 = murmur3(item + ":" + (seed+1))  // MurmurHash3 (slower, better distribution)

for (let i = 0; i < hashCount; i++) {
  position = (h1 + i * h2) % size
}
```

This gives us k pseudo-independent hash positions with O(1) additional computation per position.

### Size Calculation

```
Expected items (n): 400,000
False positive rate (p): 0.015 (1.5%)
Optimal size: m = -n × ln(p) / (ln(2))² = ~1,200,000 bits ≈ 150KB
Optimal hash count: k = (m/n) × ln(2) ≈ 7
```

Actual size in JavaScript: `Uint8Array(Math.ceil(1,200,000 / 8))` ≈ 150KB for the bit array + ~2KB overhead.

### Feed Manager

The `FeedManager`:

1. **Initializes:** Loads saved Bloom filter from `chrome.storage.local` or creates empty one
2. **Downloads:** Periodically fetches phishing domain lists from public feeds
3. **Updates:** Adds new domains to the Bloom filter
4. **Saves:** Persists updated filter to `chrome.storage.local`

Feeds (from `constants.ts`):
- `https://openphish.com/feed.txt`
- `https://phishstats.info/phish_score.csv`
- Community feed from GitHub

Update interval: 30 minutes (configurable via `ML_DEFAULTS.FEED_UPDATE_INTERVAL_MS`)

---

# 10. Milestone 8: Python Training Pipeline

**Goal:** Create a complete Python ML pipeline for training models and exporting them to TensorFlow.js format. This pipeline is run by developers, not users — it produces the model files bundled with the extension.

**Status:** 🔧 NOT STARTED (directory structure created, scripts need implementation)

## Directory Structure

```
python/
├── requirements.txt           # Python dependencies
├── train_url_model.py         # Train character-level CNN for URL classification
├── train_dom_model.py         # Train TF-IDF + dense NN for page text
├── train_ensemble.py          # Learn optimal fusion weights
├── export_to_tfjs.py          # Convert Keras models → TF.js format
├── evaluate.py                # Evaluate models on test sets
└── dataset/
    ├── download_datasets.py   # Download PhishTank, OpenPhish, Alexa
    └── preprocess.py          # Clean, tokenize, split datasets
```

## Requirements (`requirements.txt`)

```txt
tensorflow>=2.17.0
tensorflowjs>=4.22.0
numpy>=1.26.0
pandas>=2.2.0
scikit-learn>=1.5.0
requests>=2.31.0
beautifulsoup4>=4.12.0
matplotlib>=3.8.0
seaborn>=0.13.0
```

## Training Scripts (to be implemented)

### `train_url_model.py`

Downloads phishing URLs (PhishTank, OpenPhish) and legitimate URLs (Umbrella Top 1M), trains a character-level CNN, exports to TF.js.

**Architecture in Keras:**

```python
inputs = keras.Input(shape=(200,), dtype=tf.int32)
x = keras.layers.Embedding(128, 128)(inputs)
conv3 = keras.layers.Conv1D(256, 3, activation='relu', padding='same')(x)
conv3 = keras.layers.GlobalMaxPooling1D()(conv3)
conv5 = keras.layers.Conv1D(256, 5, activation='relu', padding='same')(x)
conv5 = keras.layers.GlobalMaxPooling1D()(conv5)
x = keras.layers.Concatenate()([conv3, conv5])
x = keras.layers.Dense(128, activation='relu')(x)
x = keras.layers.Dropout(0.5)(x)
outputs = keras.layers.Dense(1, activation='sigmoid')(x)
model = keras.Model(inputs, outputs)
model.compile(optimizer='adam', loss='binary_crossentropy',
              metrics=['accuracy', keras.metrics.AUC()])
```

**Expected metrics:** 94-97% accuracy, 0.97-0.99 AUC-ROC

### `train_dom_model.py`

Extracts visible text from HTML pages, trains TF-IDF vectorizer + dense neural network.

```python
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
X_train = vectorizer.fit_transform(texts_train)

model = keras.Sequential([
    keras.layers.Dense(128, activation='relu', input_shape=(5000,)),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(64, activation='relu'),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(1, activation='sigmoid'),
])
```

**Key output:** Exports vocabulary + IDF values as JSON for the TypeScript `TfidfVectorizer`.

### `train_ensemble.py`

Collects all 11 engine scores on a labeled dataset (requires running engines or simulating them), trains logistic regression.

```python
model = LogisticRegression(penalty='l2', C=1.0, class_weight='balanced')
model.fit(X_engine_scores, y_labels)

# Export: weights per engine + bias
weights = {engine_id: coef for engine_id, coef in zip(engine_ids, model.coef_[0])}
```

### `export_to_tfjs.py`

Converts trained Keras `.h5` models to TF.js format:

```python
import tensorflowjs as tfjs
model = tf.keras.models.load_model('url_cnn_model.h5')
tfjs.converters.save_keras_model(model, '../src/models/url-cnn/')
```

Also exports metadata (accuracy, version, training date) to `metadata.json`.

---

# 11. Milestone 9: Testing & Quality Assurance

**Goal:** Ensure every component works correctly, handles errors gracefully, and meets performance budgets.

**Status:** 🔧 NOT STARTED (test files planned, directory structure created)

## Test Files to Create

| File | Tests | Priority |
|------|-------|----------|
| `tests/unit/engines/ml/ml-model-engine.test.ts` | TF.js init, lazy loading, timeout, fallback, status tracking | High |
| `tests/unit/engines/ml/url-ml-engine.test.ts` | URL tokenization, preprocessing edge cases, attribution extraction | High |
| `tests/unit/engines/ml/dom-ml-engine.test.ts` | Text extraction (strip scripts/styles), TF-IDF vectorization | High |
| `tests/unit/engines/ml/ensemble-engine.test.ts` | Score computation, engine contribution %, confidence, fallback | High |
| `tests/unit/threat-intel/bloom-filter.test.ts` | Add/has, false positive rate, serialization, empty filter | High |
| `tests/unit/threat-intel/feed-manager.test.ts` | Feed parsing (OpenPhish, CSV), domain extraction | Medium |
| `tests/integration/analysis-pipeline.test.ts` | Full 11-engine + ensemble flow, ML engine failure isolation | Medium |
| `tests/performance/analysis-perf.test.ts` | Timing budgets for each engine + full analysis | Medium |
| `tests/e2e/phishing-detection.test.ts` | Puppeteer tests with real test pages | Low (future) |

## Key Test Scenarios

### MLModelEngine Base

```
✓ Engine returns score=0, confidence=0 when TF.js fails to load
✓ Engine returns fallback result when model file is missing
✓ Engine times out and returns fallback after PERFORMANCE_BUDGETS.MAX_ENGINE_TIME
✓ Engine loads model lazily (no init in constructor)
✓ Engine pre-warms model on first inference
✓ Engine status reports correct inference count and latency average
✓ Engine unloads model and frees memory on clearCache()
```

### URL Tokenization

```
✓ "https://example.com/login" → first char is 'e' → correct ID
✓ "EXAMPLE" → lowercase → "example" → correct IDs
✓ Protocol is stripped: "https://x.com" == "http://x.com"
✓ URL >200 chars → truncated to 200
✓ URL <200 chars → padded with zeros
✓ Unknown characters → mapped to special unknown token ID
```

### DOM Text Extraction

```
✓ <script> blocks are removed
✓ <style> blocks are removed
✓ HTML tags are stripped
✓ HTML entities decoded (&amp; → &)
✓ Whitespace normalized (multiple spaces → single space)
✓ Text limited to 10,000 characters
✓ Empty HTML → empty string
```

### Ensemble

```
✓ Score is always in [0, 1] range
✓ All engines' contributions sum to 100%
✓ High-confidence engines contribute more than low-confidence
✓ Fallback weights used when config fails to load
✓ ML participation bonus correctly computed
```

### Bloom Filter

```
✓ Added items always return true (has returns true)
✓ Items not added return false (with high probability)
✓ False positive rate is below 1.5% for 10,000 item test
✓ Serialize → deserialize preserves all added items
✓ Empty filter returns false for every lookup
✓ Large batch (100K items) completes within 100ms
```

---

# 12. Milestone 10: Performance Optimization

**Goal:** Meet all performance budgets for ML inference. ML must not degrade the user experience.

## Budget Targets

| Operation | Hard Budget | Target | Measured By |
|-----------|-------------|--------|-------------|
| TF.js initialization | 1000ms | <300ms | First call to `initializeTFJS()` |
| Model loading | 1000ms | <500ms | `fetch()` + `loadGraphModel()` + pre-warm |
| URL-CNN inference | 200ms | <50ms | Single `predictAsync()` call |
| DOM classifier inference | 500ms | <100ms | TF-IDF + `predictAsync()` |
| Full analysis (all 11 engines) | 5000ms | <2000ms | `EngineManager.analyzeAll()` |
| Ensemble scoring | 10ms | <1ms | Dot product + sigmoid |
| Total ML memory | 10MB | ~4MB | All loaded models + TF.js runtime |

## Optimization Strategies

### 1. Code Splitting (Already Implemented)

Using dynamic `import()` for TF.js means the initial extension bundle is not affected by ML dependencies. TF.js (~300KB) is fetched only when an ML engine first runs.

### 2. Model Quantization (Planned)

TF.js supports **float16 quantization** — converting 32-bit float weights to 16-bit. This:
- Halves model size (~600KB → ~300KB total)
- Has minimal accuracy impact (<0.5% degradation)
- Speeds up inference on GPUs

Implementation: Add `quantize: true` flag to `export_to_tfjs.py`.

### 3. Shared TF.js Context (Planned)

Both ML engines currently import TF.js independently. We can create a shared singleton:

```typescript
// Shared TF.js context
class TFJSContext {
  private static instance: any = null
  static async get(): Promise<any> {
    if (!this.instance) {
      this.instance = await import('@tensorflow/tfjs-core')
      // ... set backend, etc.
    }
    return this.instance
  }
}
```

This avoids re-initializing the backend for each engine.

### 4. Inference Result Caching (Planned)

If the same URL is analyzed twice within 30 seconds, return cached result:

```typescript
// In MLModelEngine:
private resultCache = new Map<string, { result: InferenceResult; timestamp: number }>()

async runMLInference(context): Promise<InferenceResult> {
  const cacheKey = context.url
  const cached = this.resultCache.get(cacheKey)
  if (cached && Date.now() - cached.timestamp < 30000) {
    return cached.result
  }
  // ... actual inference ...
  this.resultCache.set(cacheKey, { result, timestamp: Date.now() })
  return result
}
```

### 5. WebGL Priority (Already Implemented)

WebGL backend is 3-10x faster than CPU for neural network inference. We always try it first.

### 6. Model Size Targets

Keep individual models under 500KB each. If a model exceeds this:
- Reduce embedding dimension (128 → 64)
- Reduce number of filters (256 → 128)
- Reduce dense layer units (128 → 64)

---

# 13. Appendix A: File Inventory

## New Files Created

| # | File | Status | Lines |
|---|------|--------|-------|
| 1 | `src/shared/types/models.ts` | ✅ Done | ~100 |
| 2 | `src/background/engines/ml/index.ts` | ✅ Done | ~5 |
| 3 | `src/background/engines/ml/ml-model-engine.ts` | ✅ Done | ~220 |
| 4 | `src/background/engines/ml/url-ml-engine.ts` | ✅ Done | ~180 |
| 5 | `src/background/engines/ml/dom-ml-engine.ts` | ✅ Done | ~175 |
| 6 | `src/background/engines/ml/ensemble-engine.ts` | ✅ Done | ~140 |
| 7 | `src/background/engines/ml/tfidf.ts` | ✅ Done | ~90 |
| 8 | `src/background/threat-intel/bloom-filter.ts` | ✅ Done | ~170 |
| 9 | `src/background/threat-intel/feed-manager.ts` | ✅ Done | ~140 |
| 10 | `src/background/threat-intel/index.ts` | 🔧 Pending | ~5 |
| 11 | `plan.md` (this file) | ✅ Done | ~700+ |
| 12-20 | Test files (9 files) | 🔧 Pending | ~500 total |
| 21-26 | Python scripts (6 files) | 🔧 Pending | ~800 total |
| 27 | `python/requirements.txt` | 🔧 Pending | ~12 |
| 28-30 | Model placeholder files | 🔧 Pending | ~3 |
| 31 | `src/background/engines/ml/tfidf.ts` | ✅ Done | ~90 |

## Modified Files

| # | File | Change | Status |
|---|------|--------|--------|
| 1 | `src/shared/constants.ts` | Added ML paths, defaults, keyword categories | ✅ Done |
| 2 | `src/shared/types/engines.ts` | Added `pageText`, `urlTokenIds`, `enableML` to EngineContext | ✅ Done |
| 3 | `src/background/engines/index.ts` | Register 2 ML engines, return ensemble result | ✅ Done |
| 4 | `src/background/risk/risk-engine.ts` | Accept ensemble parameter | 🔧 Pending |
| 5 | `src/background/index.ts` | Pass ensemble result to risk engine | 🔧 Pending |
| 6 | `package.json` | Add TF.js deps, ML training scripts | 🔧 Pending |
| 7 | `vite.config.ts` | Externalize TF.js from bundling | 🔧 Pending |

---

# 14. Appendix B: Dependency List

## Production Dependencies (npm) — Already Installed

| Package | Version | Purpose | Gzip Size |
|---------|---------|---------|-----------|
| `@tensorflow/tfjs-core` | ^4.22.0 | Core tensor computation engine | ~80KB |
| `@tensorflow/tfjs-backend-cpu` | ^4.22.0 | CPU inference backend (always available) | ~85KB |
| `@tensorflow/tfjs-converter` | ^4.22.0 | Load TF SavedModel/GraphModel format | ~15KB |
| `@tensorflow/tfjs-backend-webgl` | ^4.22.0 | WebGL GPU backend (3-10x faster) | ~60KB |
| **Total added** | | | **~240KB gzip** |

## Python Training Dependencies (Development Only)

| Package | Purpose |
|---------|---------|
| `tensorflow>=2.17.0` | Training URL-CNN and DOM models |
| `tensorflowjs>=4.22.0` | Export Keras models to TF.js format |
| `numpy>=1.26.0` | Array operations, data manipulation |
| `pandas>=2.2.0` | Dataset loading and preprocessing |
| `scikit-learn>=1.5.0` | TF-IDF vectorizer, ensemble logistic regression |
| `requests>=2.31.0` | Download datasets from PhishTank, OpenPhish |
| `beautifulsoup4>=4.12.0` | HTML parsing for DOM model training |
| `matplotlib>=3.8.0` | Training visualization (loss curves, confusion matrix) |
| `seaborn>=0.13.0` | Statistical data visualization |
| `tld>=0.13` | Extract TLD from URLs for dataset filtering |

---

# 15. Appendix C: Glossary

| Term | Definition |
|------|-----------|
| **TF.js** | TensorFlow.js — JavaScript library for running ML models in the browser |
| **CNN** | Convolutional Neural Network — a type of neural network good at detecting patterns in sequences (like URLs) |
| **Character-level CNN** | A CNN that processes text character-by-character rather than word-by-word |
| **TF-IDF** | Term Frequency-Inverse Document Frequency — a numerical statistic that reflects how important a word is to a document in a collection |
| **Sigmoid** | An activation function that squashes any real number to the range [0, 1], used for binary classification output |
| **Logistic Regression** | A statistical model that uses a logistic function (sigmoid) to model binary dependent variables |
| **Ensemble** | A combination of multiple models whose predictions are fused into a single score |
| **Bloom Filter** | A space-efficient probabilistic data structure for testing set membership |
| **False Positive (FP)** | When the system flags a legitimate site as phishing (bad for user trust) |
| **False Negative (FN)** | When the system fails to flag an actual phishing site (bad for security) |
| **AUC-ROC** | Area Under the Receiver Operating Characteristic curve — a metric for binary classifier performance |
| **MCC** | Matthews Correlation Coefficient — a balanced metric for binary classification, robust to class imbalance |
| **MV3** | Manifest V3 — the latest Chrome extension platform specification |
| **WebGL** | Web Graphics Library — a JavaScript API for rendering graphics, used by TF.js for GPU-accelerated inference |
| **Service Worker** | The background script in MV3 extensions that handles events and runs independently of the browser UI |
| **Content Script** | A script injected into web pages that can access and modify the page DOM |
| **Dynamic Import** | A JavaScript feature (`import()`) that loads modules on-demand rather than eagerly at startup |
| **Tree Shaking** | A build optimization that removes unused code from the final bundle |
| **Lazy Loading** | Deferring the initialization of a resource (like a model) until it is first needed |
