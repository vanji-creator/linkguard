"""
evaluate.py — Evaluate the trained model on the held-out test set.

Outputs:
  • Classification report (precision, recall, F1 per class)
  • Confusion matrix PNG  → model_output/confusion_matrix.png
  • Per-class ROC curves  → model_output/roc_curves.png
  • Threshold analysis    → model_output/threshold_analysis.txt

Usage:
    python train/evaluate.py [--checkpoint path/to/model.pt]
"""

import sys
import argparse
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader
from transformers import AutoTokenizer
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, ConfusionMatrixDisplay
)
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")  # headless

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    PROCESSED_DIR, MODEL_DIR, BATCH_SIZE,
    ID2LABEL, NUM_LABELS, BASE_MODEL,
)
from train.dataset import URLDataset
from train.model import HybridURLClassifier


def run_inference(model, loader, device):
    model.eval()
    all_logits, all_labels = [], []

    with torch.no_grad():
        for batch in loader:
            input_ids      = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            url_features   = batch["url_features"].to(device)
            labels         = batch["label"]

            logits = model(input_ids, attention_mask, url_features)
            all_logits.append(logits.cpu())
            all_labels.append(labels)

    logits = torch.cat(all_logits, dim=0)
    labels = torch.cat(all_labels, dim=0).numpy()
    probs  = torch.softmax(logits, dim=-1).numpy()
    preds  = np.argmax(probs, axis=1)
    return probs, preds, labels


def plot_confusion_matrix(preds, labels, out_path: Path):
    class_names = [ID2LABEL[i] for i in range(NUM_LABELS)]
    cm = confusion_matrix(labels, preds, normalize="true")
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_names)
    fig, ax = plt.subplots(figsize=(7, 6))
    disp.plot(ax=ax, colorbar=True, cmap="Blues", values_format=".2f")
    ax.set_title("LinkGuard Classifier — Normalized Confusion Matrix", pad=12)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  Saved: {out_path}")


def plot_roc_curves(probs, labels, out_path: Path):
    class_names = [ID2LABEL[i] for i in range(NUM_LABELS)]
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ["steelblue", "darkorange", "firebrick"]

    for i, (name, color) in enumerate(zip(class_names, colors)):
        y_bin = (labels == i).astype(int)
        fpr, tpr, _ = roc_curve(y_bin, probs[:, i])
        auc = roc_auc_score(y_bin, probs[:, i])
        ax.plot(fpr, tpr, color=color, lw=2,
                label=f"{name} (AUC = {auc:.3f})")

    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — One-vs-Rest")
    ax.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  Saved: {out_path}")


def threshold_analysis(probs, labels, out_path: Path):
    """
    For each confidence threshold, compute: what % of URLs are sent to VT,
    and what % of decisions are correct (precision at threshold).
    This tells us the optimal CONFIDENCE_THRESHOLD setting.
    """
    thresholds = np.arange(0.5, 1.0, 0.05)
    lines = ["Threshold | Coverage | Precision | Dangerous Recall\n" + "-" * 55]

    for t in thresholds:
        max_conf = probs.max(axis=1)
        confident_mask = max_conf >= t
        coverage  = confident_mask.mean()
        if confident_mask.sum() == 0:
            continue
        correct   = (np.argmax(probs[confident_mask], axis=1) == labels[confident_mask]).mean()
        # Recall on dangerous class (most important — we don't want to miss threats)
        dangerous_mask = (labels == 2)
        if dangerous_mask.sum() > 0:
            dangerous_recall = (
                (np.argmax(probs[dangerous_mask & confident_mask], axis=1) == 2).sum()
                / dangerous_mask.sum()
            )
        else:
            dangerous_recall = float("nan")

        lines.append(
            f"  {t:.2f}    | {coverage:.2%}    | {correct:.2%}     | {dangerous_recall:.2%}"
        )

    report = "\n".join(lines)
    print(report)
    with open(out_path, "w") as f:
        f.write(report)
    print(f"\n  Saved: {out_path}")


def main(checkpoint: str | None = None):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n=== LinkGuard — Evaluation ===")
    print(f"Device: {device}")

    checkpoint_path = Path(checkpoint) if checkpoint else MODEL_DIR / "best_model" / "model.pt"
    if not checkpoint_path.exists():
        print(f"✗ Checkpoint not found: {checkpoint_path}")
        sys.exit(1)

    tokenizer_path = checkpoint_path.parent
    print(f"Loading tokenizer from {tokenizer_path}...")
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)

    print("Loading test dataset...")
    test_ds     = URLDataset(PROCESSED_DIR / "test.parquet", tokenizer)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE * 2,
                             shuffle=False, num_workers=4)
    print(f"  Test set: {len(test_ds):,} samples")

    print(f"Loading model from {checkpoint_path}...")
    model = HybridURLClassifier()
    model.load_state_dict(torch.load(checkpoint_path, map_location=device))
    model = model.to(device)

    print("\nRunning inference...")
    probs, preds, labels = run_inference(model, test_loader, device)

    # ── Classification report ─────────────────────────────────────────────────
    class_names = [ID2LABEL[i] for i in range(NUM_LABELS)]
    report = classification_report(
        labels, preds,
        labels=list(range(NUM_LABELS)),
        target_names=class_names,
        digits=4,
        zero_division=0,
    )
    print(f"\n{report}")
    report_path = MODEL_DIR / "classification_report.txt"
    with open(report_path, "w") as f:
        f.write(report)

    # ── Visualizations ────────────────────────────────────────────────────────
    print("Generating plots...")
    plot_confusion_matrix(preds, labels, MODEL_DIR / "confusion_matrix.png")
    plot_roc_curves(probs, labels, MODEL_DIR / "roc_curves.png")

    print("\nThreshold analysis:")
    threshold_analysis(probs, labels, MODEL_DIR / "threshold_analysis.txt")

    print(f"\n✓ All outputs saved to {MODEL_DIR}/")
    print("  Next: python train/export_onnx.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=str, default=None)
    args = parser.parse_args()
    main(args.checkpoint)
