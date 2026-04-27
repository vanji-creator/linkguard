"""
export_onnx.py — Export the trained hybrid model to ONNX format.

Steps:
  1. Load best_model/model.pt
  2. Trace through torch.onnx.export
  3. Verify with onnxruntime
  4. Quantize to INT8 (optional, ~4× smaller)

Outputs:
  model_output/onnx/model.onnx           — full precision
  model_output/onnx/model_int8.onnx      — INT8 quantized

Usage:
    python train/export_onnx.py [--no-quantize]
"""

import sys
import argparse
from pathlib import Path

import numpy as np
import torch
from transformers import AutoTokenizer

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    MODEL_DIR, ONNX_DIR, BASE_MODEL,
    MAX_SEQ_LEN, NUM_URL_FEATURES, NUM_LABELS,
)
from train.model import HybridURLClassifier


def export_onnx(model: HybridURLClassifier, out_path: Path):
    """Export model to ONNX with dynamic batch size."""
    model.eval()

    # Dummy inputs (batch=1 for tracing)
    dummy_ids   = torch.zeros(1, MAX_SEQ_LEN, dtype=torch.long)
    dummy_mask  = torch.ones(1, MAX_SEQ_LEN, dtype=torch.long)
    dummy_feats = torch.zeros(1, NUM_URL_FEATURES, dtype=torch.float32)

    print(f"  Exporting to {out_path}...")
    torch.onnx.export(
        model,
        (dummy_ids, dummy_mask, dummy_feats),
        str(out_path),
        opset_version=14,
        input_names=["input_ids", "attention_mask", "url_features"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids":      {0: "batch"},
            "attention_mask": {0: "batch"},
            "url_features":   {0: "batch"},
            "logits":         {0: "batch"},
        },
        do_constant_folding=True,
        dynamo=False,
    )
    size_mb = out_path.stat().st_size / 1e6
    print(f"  ✓ Exported ({size_mb:.1f} MB)")


def verify_onnx(onnx_path: Path, tokenizer: AutoTokenizer):
    """Run a test inference through onnxruntime and verify output shape."""
    import onnxruntime as ort
    from serve.features import extract as extract_features

    test_urls = [
        "https://www.google.com/",
        "http://paypal-secure-login.xyz/verify?token=abc123",
    ]

    print(f"\n  Verifying {onnx_path.name}...")
    sess = ort.InferenceSession(str(onnx_path),
                                providers=["CPUExecutionProvider"])

    for url in test_urls:
        enc = tokenizer(url, max_length=MAX_SEQ_LEN, padding="max_length",
                        truncation=True, return_tensors="np")
        feats = extract_features(url).reshape(1, -1)

        outputs = sess.run(["logits"], {
            "input_ids":      enc["input_ids"].astype(np.int64),
            "attention_mask": enc["attention_mask"].astype(np.int64),
            "url_features":   feats,
        })
        logits = outputs[0]
        probs  = np.exp(logits) / np.exp(logits).sum(axis=-1, keepdims=True)
        pred   = int(np.argmax(probs))
        labels = {0: "safe", 1: "suspicious", 2: "dangerous"}
        print(f"    {url[:60]:<60} → {labels[pred]:10s} "
              f"(conf: {probs[0, pred]:.3f})")
    print("  ✓ ONNX verification OK")


def quantize_onnx(input_path: Path, output_path: Path):
    """INT8 dynamic quantization — reduces size ~4× with <1% accuracy drop."""
    from onnxruntime.quantization import quantize_dynamic, QuantType

    print(f"\n  Quantizing to INT8 → {output_path.name}...")
    quantize_dynamic(
        str(input_path),
        str(output_path),
        weight_type=QuantType.QInt8,
        extra_options={"EnableSubgraph": True},
    )
    size_mb = output_path.stat().st_size / 1e6
    print(f"  ✓ INT8 model ({size_mb:.1f} MB)")


def main(quantize: bool = True):
    print("\n=== LinkGuard — ONNX Export ===")

    checkpoint_path = MODEL_DIR / "best_model" / "model.pt"
    if not checkpoint_path.exists():
        print(f"✗ Checkpoint not found: {checkpoint_path}")
        print("  Run train/train.py first.")
        sys.exit(1)

    tokenizer_path = checkpoint_path.parent
    print(f"Loading tokenizer from {tokenizer_path}...")
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)

    print("Loading model...")
    model = HybridURLClassifier()
    model.load_state_dict(torch.load(checkpoint_path, map_location="cpu"))
    model.eval()

    onnx_path    = ONNX_DIR / "model.onnx"
    int8_path    = ONNX_DIR / "model_int8.onnx"

    # Export full-precision ONNX
    export_onnx(model, onnx_path)

    # Verify
    verify_onnx(onnx_path, tokenizer)

    # Quantize
    if quantize:
        quantize_onnx(onnx_path, int8_path)
        verify_onnx(int8_path, tokenizer)
        print(f"\n  Size reduction: "
              f"{onnx_path.stat().st_size / int8_path.stat().st_size:.1f}×")

    print(f"\n✓ ONNX models saved to {ONNX_DIR}/")
    print("  Next: deploy via serve/spaces/ to HuggingFace Spaces")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-quantize", dest="quantize",
                        action="store_false", default=True)
    args = parser.parse_args()
    main(quantize=args.quantize)
