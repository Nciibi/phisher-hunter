# Phisher Hunter — ML Model Upgrade Plan

> **Goal:** Transform Phisher Hunter from a purely heuristic rule-based phishing detector into a hybrid system combining **machine learning models** with existing **expert-crafted heuristics**, achieving 98%+ detection accuracy while maintaining on-device privacy and sub-500ms analysis time.

> **Strategy:** Add ML gradually — start with URL classification, then DOM content analysis, then ensemble scoring. Each phase independently deployable and testable.

---

## 1. What We Have Today

**Phisher Hunter** is a Chrome MV3 extension with **9 purely heuristic detection engines**:
- `credential-canary`, `visual-fingerprint`, `url-entropy`, `css-deception`, `language-matrix`, `script-timeseries`, `certificate-anomaly`, `temporal-clustering`, `interactive-honeypot`

All 9 use hand-written rules and pattern matching. Risk scoring uses **hardcoded static weights** chosen by developer intuition.

**No ML models exist** — no TensorFlow.js, no ONNX, no model inference of any kind.

## 2. Target Architecture

```
                    ┌─────────────────────────┐
                    │     EngineManager        │
                    │  (runs all in parallel)  │
                    └──────┬──────────┬───────┘
                           │          │
              ┌────────────┘          └────────────┐
              ▼                                     ▼
   ┌─────────────────────┐             ┌─────────────────────┐
   │ 9 Heuristic Engines │             │ 2 ML Engines (NEW)  │
   │ (unchanged)         │             │                     │
   │                     │             │ • UrlMLModelEngine  │
   │ • credential-canary │             │ • DomMLModelEngine  │
   │ • visual-fingerprint│             └──────────┬──────────┘
   │ • url-entropy       │                        │
   │ • css-deception     │                        │
   │ • language-matrix   │                        │
   │ • script-timeseries │                        │
   │ • certificate-anomal│                        │
   │ • temporal-cluster  │                        │
   │ • interactive-honeyp│                        │
   └──────────┬──────────┘                        │
              │                                   │
              └──────────┬───────────────────────┘
                         ▼
              ┌─────────────────────┐
              │   EnsembleEngine    │  ← NEW: learned weights
              │  (logistic fusion)  │
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │     RiskEngine      │
              │  (uses ensemble     │
              │   score as primary) │
              └─────────────────────┘
```

## 3. What We're Adding (Summary)

| Component | File(s) | Description |
|-----------|---------|-------------|
| ML Types & Interfaces | `src/shared/types/models.ts` | `ModelConfig`, `InferenceResult`, `EnsembleConfig`, etc. |
| MLModelEngine (base) | `src/background/engines/ml/ml-model-engine.ts` | Abstract base — handles TF.js lifecycle, lazy loading, timeout, fallback |
| UrlMLModelEngine | `src/background/engines/ml/url-ml-engine.ts` | Character-level CNN running in TF.js |
| DomMLModelEngine | `src/background/engines/ml/dom-ml-engine.ts` | TF-IDF + Dense NN on page text |
| EnsembleEngine | `src/background/engines/ml/ensemble-engine.ts` | Learned logistic regression fusion of all 11 engines |
| BloomFilter | `src/background/threat-intel/bloom-filter.ts` | Space-efficient phishing domain lookup |
| FeedManager | `src/background/threat-intel/feed-manager.ts` | Periodic threat feed downloader |
| TF-IDF Vectorizer (TS) | `src/background/engines/ml/tfidf.ts` | JavaScript implementation of scikit-learn's TF-IDF |
| Model files | `src/models/url-cnn/`, `src/models/dom-classifier/`, `src/models/ensemble/` | Bundled TF.js models + weights |
| Training scripts | `python/` directory | `train_url_model.py`, `train_dom_model.py`, `train_ensemble.py`, `export_to_tfjs.py` |

## 4. Training Pipeline (Python)

### URL Model (`python/train_url_model.py`)
- **Architecture:** Character-level CNN: Embedding(128) → Conv1D(256,k=3) + Conv1D(256,k=5) → GlobalMaxPool → Dense(128) → Dense(1,sigmoid)
- **Input:** URL character IDs (max 200 chars, vocab 128)
- **Output:** Phishing probability [0,1]
- **Target accuracy:** 94-97%
- **Target size:** ~300KB after TF.js export
- **Training data:** PhishTank (phishing) + Cisco Umbrella Top 100K (legitimate)

### DOM Model (`python/train_dom_model.py`)
- **Architecture:** TF-IDF(5000 features) → Dense(128,ReLU) → Dropout(0.3) → Dense(64,ReLU) → Dense(1,sigmoid)
- **Input:** Cleaned visible page text (max 10000 chars)
- **Output:** Phishing probability [0,1]
- **Target accuracy:** 90-93%
- **Target size:** ~250KB (vectorizer config + weights)
- **Key decision:** TF-IDF vectorizer runs in TypeScript (exported vocabulary JSON), only NN is TF.js

### Ensemble Weights (`python/train_ensemble.py`)
- **Model:** Logistic regression (L2-regularized) on all 11 engine scores
- **Input:** 11 feature vector (9 heuristic scores + 2 ML scores)
- **Output:** 11 learned weights + bias term
- **Target:** Outperforms static weights by ~2-5% absolute accuracy

## 5. Engines Implementation

### MLModelEngine (abstract base)
- Extends `BaseEngine` — plugs into existing EngineManager seamlessly
- Lazy loads TF.js on first inference (dynamic `import('@tensorflow/tfjs-core')`)
- Tries WebGL backend first, falls back to CPU
- 2000ms inference timeout (matches PERFORMANCE_BUDGETS.MAX_ENGINE_TIME)
- Graceful fallback: returns score=0, confidence=0 on any failure
- Pre-warms model with dummy input after loading
- `getStatus()` for diagnostics, `unloadModel()` to free memory

### UrlMLModelEngine
- Preprocesses URL: lowercase, strip protocol/`www.`, tokenize characters, pad/truncate to 200
- Runs character CNN inference via `model.predictAsync()`
- Extracts attributions: digit count in domain, suspicious TLD, subdomain count, URL shorteners, IP addresses
- Builds human-readable reasons from attributions

### DomMLModelEngine
- Extracts visible text: strip `<script>`, `<style>`, `<svg>`, HTML tags, normalize whitespace
- Loads TF-IDF vocabulary from `models/dom-classifier/tfidf_config.json`
- Vectorizes text with TypeScript TF-IDF implementation (sublinear TF, L2 normalization)
- Runs dense NN inference
- Extracts key phrases: urgency words, credential words, brand references

### EnsembleEngine
- Loads learned weights from `models/ensemble/weights.json`
- Computes: `score = sigmoid(Σ(weight_i × score_i) + bias)`
- Calculates per-engine contribution percentages
- Computes confidence: distance from decision boundary + engine agreement + ML participation bonus
- Falls back to static weights if config fails to load

## 6. Bloom Filter (Threat Intelligence)

- Space-efficient probabilistic data structure for local phishing domain lookup
- Size: ~1.2MB for 400K domains at 1.5% false positive rate
- Uses double hashing (FNV-1a + MurmurHash3) for k independent hash positions
- Serializes to/from `chrome.storage.local` for persistence across sessions
- Updated every 30 minutes from OpenPhish, PhishStats, community feeds

## 7. Integration Points

### EngineManager (`src/background/engines/index.ts`)
- Register 2 new ML engines alongside existing 9 → 11 total
- `analyzeAll()` returns `{ engineResults, ensembleResult }` instead of just engine results
- New `getMLStatus()`, enhanced `clearAllCaches()` (unloads ML models)

### RiskEngine (`src/background/risk/risk-engine.ts`)
- Accepts `EnsembleResult` as new parameter
- Uses ensemble score as primary risk signal
- Falls back to static weighted scoring if ensemble confidence < 0.3

### Background entry (`src/background/index.ts`)
- Passes ensemble result to risk engine
- New message types: `GET_ML_STATUS`, `RELOAD_ENSEMBLE`

### EngineContext (`src/shared/types/engines.ts`)
- New fields: `pageText?`, `urlTokenIds?`, `enableML?`

## 8. Dependencies

### Production (npm)
| Package | Purpose | Size (gzip) |
|---------|---------|-------------|
| `@tensorflow/tfjs-core` | Core TF engine | ~80KB |
| `@tensorflow/tfjs-backend-cpu` | CPU backend | ~85KB |
| `@tensorflow/tfjs-converter` | Load GraphModel | ~15KB |
| `@tensorflow/tfjs-backend-webgl` | GPU backend | ~60KB |

### Python (training only)
`tensorflow`, `tensorflowjs`, `numpy`, `pandas`, `scikit-learn`, `requests`, `beautifulsoup4`

## 9. Performance Budgets

| Operation | Budget | Target |
|-----------|--------|--------|
| TF.js init + model load | <1000ms | <300ms |
| URL-CNN inference | <200ms | <50ms |
| DOM classifier inference | <500ms | <100ms |
| Full analysis (all 11 engines) | <5000ms | <2000ms |
| Ensemble scoring | <10ms | <1ms |
| Total memory (all ML) | <10MB | ~4MB |

## 10. Testing

| Test Type | What | How |
|-----------|------|-----|
| Unit: preprocessing | URL tokenization, text cleaning, TF-IDF vectorization | Jest/Vitest with mock data |
| Unit: ML fallback | Graceful degradation when model fails/timeout | Mock TF.js import to throw |
| Unit: Bloom filter | Set membership, false positive rate, serialization | 10K item tests |
| Unit: Ensemble | Score range, weight application, contribution calc | Mock engine results |
| Integration: pipeline | All 11 engines + ensemble produce valid results | Full EngineManager call |
| Integration: risk | Ensemble score flows correctly to AnalysisResult | RiskEngine with ensemble input |
| Performance | Each engine + full analysis within budgets | `performance.now()` assertions |
| E2E | Real phishing URL detection via Puppeteer | Chrome with extension loaded |

## 11. Project Structure (New/Modified Files)

```
src/
├── background/
│   ├── engines/
│   │   ├── index.ts              ← MODIFIED: register ML engines, return ensemble
│   │   ├── ml/                   ← NEW directory
│   │   │   ├── ml-model-engine.ts
│   │   │   ├── url-ml-engine.ts
│   │   │   ├── dom-ml-engine.ts
│   │   │   ├── ensemble-engine.ts
│   │   │   ├── tfidf.ts
│   │   │   └── index.ts
│   ├── risk/
│   │   └── risk-engine.ts        ← MODIFIED: use ensemble score
│   └── threat-intel/             ← NEW directory
│       ├── bloom-filter.ts
│       ├── feed-manager.ts
│       └── index.ts
├── shared/
│   ├── types/
│   │   ├── models.ts             ← NEW: all ML-related interfaces
│   │   └── engines.ts            ← MODIFIED: add pageText, urlTokenIds, enableML
│   └── constants.ts              ← MODIFIED: add model config constants
├── models/                       ← NEW: bundled TF.js model files
│   ├── url-cnn/
│   │   ├── model.json
│   │   ├── weights.bin
│   │   └── metadata.json
│   ├── dom-classifier/
│   │   ├── model.json
│   │   ├── weights.bin
│   │   ├── tfidf_config.json
│   │   ├── vocabulary.json
│   │   └── metadata.json
│   └── ensemble/
│       └── weights.json
python/                           ← NEW: training pipeline
├── requirements.txt
├── train_url_model.py
├── train_dom_model.py
├── train_ensemble.py
├── export_to_tfjs.py
└── dataset/
    ├── download_datasets.py
    └── preprocess.py
```
