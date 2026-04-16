"""
app.py — HuggingFace Spaces FastAPI endpoint for the LinkGuard ONNX model.

Deploy this entire serve/spaces/ directory to HuggingFace Spaces
(Space type: Docker or Gradio with custom app).

Environment variables (set in Spaces settings):
    MODEL_PATH    — path to model_int8.onnx (default: ./model_int8.onnx)
    TOKENIZER_PATH — path to tokenizer dir (default: ./tokenizer)
    HF_TOKEN      — optional, for private model access

API endpoint:
    POST /scan
    Body: {"url": "https://example.com"}
    Response: {"verdict": "safe", "confidence": 0.97, "scores": {...}}

The extension calls this endpoint from checkWithAIModel() in background.js.
"""

import os
import sys
from pathlib import Path

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

# ── Load model ────────────────────────────────────────────────────────────────
MODEL_PATH     = os.getenv("MODEL_PATH",     "./model_int8.onnx")
TOKENIZER_PATH = os.getenv("TOKENIZER_PATH", "./tokenizer")
MAX_SEQ_LEN    = int(os.getenv("MAX_SEQ_LEN", "128"))
NUM_FEATURES   = int(os.getenv("NUM_FEATURES", "50"))

ID2LABEL = {0: "safe", 1: "suspicious", 2: "dangerous"}

# Lazy-load on first request (Spaces cold start)
_session   = None
_tokenizer = None


def _load():
    global _session, _tokenizer
    if _session is not None:
        return

    import onnxruntime as ort
    from transformers import AutoTokenizer

    opts = ort.SessionOptions()
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    _session = ort.InferenceSession(
        MODEL_PATH,
        sess_options=opts,
        providers=["CPUExecutionProvider"],
    )
    _tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_PATH)
    print("Model loaded.", flush=True)


def _classify(url: str) -> dict:
    """Core inference — called after model is loaded."""
    # Import features extractor from the same package
    # In Spaces, features.py is copied alongside app.py
    from features import extract as extract_features

    enc = _tokenizer(
        url,
        max_length=MAX_SEQ_LEN,
        padding="max_length",
        truncation=True,
        return_tensors="np",
    )
    feats = extract_features(url).reshape(1, -1)

    outputs = _session.run(["logits"], {
        "input_ids":      enc["input_ids"].astype(np.int64),
        "attention_mask": enc["attention_mask"].astype(np.int64),
        "url_features":   feats,
    })

    logits = outputs[0][0]
    exp    = np.exp(logits - logits.max())
    probs  = exp / exp.sum()
    pred   = int(np.argmax(probs))

    return {
        "verdict":    ID2LABEL[pred],
        "confidence": float(probs[pred]),
        "scores": {
            "safe":       float(probs[0]),
            "suspicious": float(probs[1]),
            "dangerous":  float(probs[2]),
        },
    }


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="LinkGuard URL Safety API",
    version="1.0.0",
    description="Hybrid SecureBERT + URL features classifier. 3 classes: safe / suspicious / dangerous.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Chrome extension can call from any origin
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    verdict:    str
    confidence: float
    scores:     dict


@app.on_event("startup")
async def startup_event():
    _load()


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": _session is not None}


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    _load()
    if not req.url or len(req.url) > 2048:
        raise HTTPException(status_code=400, detail="Invalid URL")
    try:
        result = _classify(req.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# For local testing: uvicorn app:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
