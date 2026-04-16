"""
local_inference.py — Run the ONNX model locally for testing.

Usage:
    python serve/local_inference.py https://www.google.com
    python serve/local_inference.py http://paypal-secure-login.xyz/verify

    # Batch mode from file (one URL per line):
    python serve/local_inference.py --file urls.txt
"""

import sys
import argparse
import time
from pathlib import Path

import numpy as np
from transformers import AutoTokenizer

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import MODEL_DIR, ONNX_DIR, MAX_SEQ_LEN, NUM_URL_FEATURES, CONFIDENCE_THRESHOLD
from serve.features import extract as extract_features

try:
    import onnxruntime as ort
    _ORT_AVAILABLE = True
except ImportError:
    _ORT_AVAILABLE = False


ID2LABEL = {0: "safe", 1: "suspicious", 2: "dangerous"}


class LinkGuardClassifier:
    """
    Lightweight ONNX inference wrapper.
    Used both for local testing and inside the HuggingFace Spaces API.
    """

    def __init__(self, model_path: str | Path | None = None,
                 tokenizer_path: str | Path | None = None,
                 use_int8: bool = True):
        if not _ORT_AVAILABLE:
            raise ImportError("onnxruntime not installed. Run: pip install onnxruntime")

        model_path     = model_path or (
            ONNX_DIR / ("model_int8.onnx" if use_int8 else "model.onnx")
        )
        tokenizer_path = tokenizer_path or (MODEL_DIR / "best_model")

        if not Path(model_path).exists():
            raise FileNotFoundError(
                f"ONNX model not found: {model_path}\n"
                "Run train/export_onnx.py first."
            )

        print(f"Loading ONNX model: {Path(model_path).name}")
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(
            str(model_path),
            sess_options=opts,
            providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
        )

        self.tokenizer = AutoTokenizer.from_pretrained(str(tokenizer_path))
        print("Ready.")

    def predict(self, url: str) -> dict:
        """
        Classify a single URL.

        Returns:
            {
                "url":        str,
                "verdict":    "safe" | "suspicious" | "dangerous",
                "confidence": float (0-1),
                "scores":     {"safe": float, "suspicious": float, "dangerous": float},
                "latency_ms": float,
            }
        """
        t0  = time.perf_counter()
        enc = self.tokenizer(
            url,
            max_length=MAX_SEQ_LEN,
            padding="max_length",
            truncation=True,
            return_tensors="np",
        )
        feats = extract_features(url).reshape(1, -1)

        outputs = self.session.run(["logits"], {
            "input_ids":      enc["input_ids"].astype(np.int64),
            "attention_mask": enc["attention_mask"].astype(np.int64),
            "url_features":   feats,
        })

        logits = outputs[0][0]
        exp    = np.exp(logits - logits.max())
        probs  = exp / exp.sum()

        pred_id    = int(np.argmax(probs))
        confidence = float(probs[pred_id])
        latency_ms = (time.perf_counter() - t0) * 1000

        return {
            "url":        url,
            "verdict":    ID2LABEL[pred_id],
            "confidence": confidence,
            "scores":     {ID2LABEL[i]: float(probs[i]) for i in range(3)},
            "latency_ms": latency_ms,
        }

    def predict_batch(self, urls: list[str]) -> list[dict]:
        """Classify multiple URLs in one ONNX batch call (faster)."""
        t0 = time.perf_counter()

        encodings = self.tokenizer(
            urls,
            max_length=MAX_SEQ_LEN,
            padding="max_length",
            truncation=True,
            return_tensors="np",
        )
        feats = np.stack([extract_features(u) for u in urls])

        outputs = self.session.run(["logits"], {
            "input_ids":      encodings["input_ids"].astype(np.int64),
            "attention_mask": encodings["attention_mask"].astype(np.int64),
            "url_features":   feats,
        })

        logits_batch = outputs[0]
        total_ms     = (time.perf_counter() - t0) * 1000
        results = []

        for i, (url, logits) in enumerate(zip(urls, logits_batch)):
            exp    = np.exp(logits - logits.max())
            probs  = exp / exp.sum()
            pred_id    = int(np.argmax(probs))
            confidence = float(probs[pred_id])
            results.append({
                "url":        url,
                "verdict":    ID2LABEL[pred_id],
                "confidence": confidence,
                "scores":     {ID2LABEL[j]: float(probs[j]) for j in range(3)},
                "latency_ms": total_ms / len(urls),
            })

        return results


def _print_result(result: dict):
    verdict = result["verdict"]
    icons   = {"safe": "✓", "suspicious": "⚠", "dangerous": "✗"}
    conf    = result["confidence"]
    below   = " (→ would fall through to VirusTotal)" if conf < CONFIDENCE_THRESHOLD else ""
    print(f"\n  {icons.get(verdict, '?')} [{verdict.upper():10s}] conf={conf:.1%}{below}")
    print(f"    URL: {result['url']}")
    print(f"    Scores: safe={result['scores']['safe']:.3f} "
          f"suspicious={result['scores']['suspicious']:.3f} "
          f"dangerous={result['scores']['dangerous']:.3f}")
    print(f"    Latency: {result['latency_ms']:.1f} ms")


def main():
    parser = argparse.ArgumentParser(description="LinkGuard local URL classifier")
    parser.add_argument("urls", nargs="*", help="URLs to classify")
    parser.add_argument("--file", type=str, help="File with one URL per line")
    parser.add_argument("--no-int8", dest="int8", action="store_false", default=True)
    args = parser.parse_args()

    clf = LinkGuardClassifier(use_int8=args.int8)

    urls = list(args.urls)
    if args.file:
        with open(args.file) as f:
            urls += [l.strip() for l in f if l.strip()]

    if not urls:
        # Demo mode
        urls = [
            "https://www.google.com/",
            "https://github.com/vanji-creator/linkguard",
            "http://paypal-secure-login.xyz/verify?session=abc123",
            "https://free-iphone-winner.tk/claim?user=vanji",
            "http://192.168.1.1/admin",
        ]
        print("Demo mode — classifying sample URLs:")

    if len(urls) == 1:
        result = clf.predict(urls[0])
        _print_result(result)
    else:
        results = clf.predict_batch(urls)
        for r in results:
            _print_result(r)


if __name__ == "__main__":
    main()
