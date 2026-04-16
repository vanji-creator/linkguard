# LinkGuard URL Safety Classifier

Hybrid model combining **SecureBERT** (cybersecurity-aware transformer) with a
**50-feature URL structural branch** for 3-class URL classification:
`safe` / `suspicious` / `dangerous`

## Architecture

```
URL → SecureBERT tokenizer → SecureBERT encoder → CLS [768]
                                                          ↘
URL → 50 hand-crafted features → MLP [64]
                                          ↗
                    Concat [832] → Classifier → 3 classes
```

The transformer gives semantic cybersecurity knowledge.
The feature branch gives lexical URL structure (entropy, subdomain depth,
brand impersonation, suspicious TLDs, phishing keywords, etc.).

---

## Setup

```bash
cd linkguard-model/
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Pipeline — Step by Step

### Step 1: Collect data (fully automated, no registration)
```bash
python data/collect.py
```
Downloads automatically:
- URLhaus (~600K malware URLs)
- OpenPhish (~5K live phishing)
- ThreatFox (~50K threat IOCs)
- PhishStats (~100K phishing, score ≥ 5, updated every 90 min)
- Tranco top-1M (safe domains)

### Step 2: Preprocess
```bash
python data/preprocess.py
```
Normalizes, deduplicates, balances classes, splits 80/10/10.
Output: `data/processed/{train,val,test}.parquet`

### Step 3: Train

**No GPU? Use Google Colab (free T4 GPU):**
1. Upload `notebooks/train_colab.ipynb` to [colab.research.google.com](https://colab.research.google.com)
2. Runtime → Change runtime type → **T4 GPU**
3. Run all cells — takes ~2 hours, saves to Google Drive

**Have a GPU locally:**
```bash
python train/train.py
```
- Downloads SecureBERT (~500MB, first run only)
- Trains for 4 epochs with differential learning rates
- Best checkpoint saved by val F1 (macro)

### Step 4: Evaluate
```bash
python train/evaluate.py
```
Outputs: classification report, confusion matrix PNG, ROC curves, threshold analysis.

### Step 5: Export to ONNX
```bash
python train/export_onnx.py
```
Output: `model_output/onnx/model_int8.onnx` (~120MB quantized)

### Step 6: Test locally
```bash
python serve/local_inference.py https://www.google.com
python serve/local_inference.py http://paypal-secure-login.xyz/verify?token=abc
```

### Step 7: Deploy to HuggingFace Spaces
1. Create a new Space at https://huggingface.co/spaces (type: Docker or FastAPI)
2. Copy these files to the Space repo:
   - `serve/spaces/app.py`
   - `serve/spaces/requirements.txt`
   - `serve/features.py`  (copy alongside app.py, renamed `features.py`)
   - `model_output/onnx/model_int8.onnx`
   - `model_output/best_model/` (tokenizer files)
3. Push to HuggingFace
4. Test: `HF_SPACE_URL=https://your-space.hf.space python serve/hf_client.py`

### Step 8: Wire into extension
1. Open `background.js`
2. Set `LG_MODEL_URL = "https://your-space.hf.space"` (line ~9)
3. Reload extension in `chrome://extensions`

---

## Directory Structure

```
linkguard-model/
├── config.py            — all hyperparameters and paths
├── requirements.txt
├── data/
│   ├── collect.py       — download all feeds
│   ├── preprocess.py    — clean, label, split
│   └── raw/             — gitignored
├── train/
│   ├── dataset.py       — PyTorch Dataset
│   ├── model.py         — HybridURLClassifier (SecureBERT + feature MLP)
│   ├── train.py         — training loop
│   ├── evaluate.py      — metrics + visualizations
│   └── export_onnx.py   — ONNX + INT8 quantization
├── serve/
│   ├── features.py      — 50-dim URL feature extractor (shared)
│   ├── local_inference.py — ONNX inference wrapper + CLI
│   ├── hf_client.py     — test the deployed Spaces API
│   └── spaces/
│       ├── app.py       — FastAPI app (deploy to HF Spaces)
│       └── requirements.txt
└── model_output/        — gitignored, checkpoints + ONNX
```

---

## Expected Performance Targets

| Metric              | Target |
|---------------------|--------|
| Macro F1            | ≥ 0.93 |
| Dangerous recall    | ≥ 0.97 |
| Safe precision      | ≥ 0.98 |
| Inference latency   | < 200ms (Spaces CPU) |
| VT quota saved      | ~80-90% |

High dangerous recall is the priority — missing a threat is worse than
a false positive (which falls through to VirusTotal anyway).
