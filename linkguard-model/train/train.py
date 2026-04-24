"""
train.py — Fine-tune the Hybrid URL Safety Classifier.

Features:
  • Mixed precision (AMP) for GPU speedup
  • Differential learning rates (lower LR for BERT layers)
  • Linear warmup + cosine decay schedule
  • Class-weighted loss to handle imbalance
  • Best checkpoint saved on val F1 (macro)
  • Gradient clipping
  • Optional Google Drive backup after each best checkpoint

Usage:
    python train/train.py [--resume path/to/checkpoint] [--backup-dir /content/drive/MyDrive/linkguard]

Output:
    model_output/best_model/   — best checkpoint (PyTorch)
    model_output/tokenizer/    — tokenizer files
    model_output/training_log.csv
"""

import sys
import csv
import time
import shutil
import argparse
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, get_cosine_schedule_with_warmup
from sklearn.metrics import f1_score, classification_report
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    BASE_MODEL, PROCESSED_DIR, MODEL_DIR,
    BATCH_SIZE, GRAD_ACCUM, LEARNING_RATE, BERT_LR,
    NUM_EPOCHS, WARMUP_RATIO, WEIGHT_DECAY, MAX_GRAD_NORM,
    LABEL2ID, ID2LABEL, NUM_LABELS, SEED,
)
from train.dataset import URLDataset
from train.model import HybridURLClassifier, count_params


def set_seed(seed: int):
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def get_class_weights(dataset: URLDataset, device: torch.device) -> torch.Tensor:
    """Inverse-frequency weights for weighted cross-entropy."""
    labels = np.array(dataset.labels)
    counts = np.bincount(labels, minlength=NUM_LABELS).astype(float)
    weights = 1.0 / (counts + 1e-6)
    weights = weights / weights.sum() * NUM_LABELS   # normalize so mean ≈ 1
    return torch.tensor(weights, dtype=torch.float32, device=device)


def make_optimizer(model: HybridURLClassifier):
    """
    Differential learning rates:
      - BERT layers → BERT_LR
      - Feature MLP + classifier → LEARNING_RATE
    """
    bert_params  = list(model.bert.parameters())
    other_params = (
        list(model.feature_branch.parameters()) +
        list(model.classifier.parameters())
    )
    return torch.optim.AdamW([
        {"params": bert_params,  "lr": BERT_LR},
        {"params": other_params, "lr": LEARNING_RATE},
    ], weight_decay=WEIGHT_DECAY)


def evaluate(model, loader, criterion, device) -> dict:
    model.eval()
    total_loss = 0.0
    all_preds, all_labels = [], []

    with torch.no_grad():
        for batch in loader:
            input_ids      = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            url_features   = batch["url_features"].to(device)
            labels         = batch["label"].to(device)

            logits = model(input_ids, attention_mask, url_features)
            loss   = criterion(logits, labels)
            total_loss += loss.item()

            preds = torch.argmax(logits, dim=-1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    avg_loss = total_loss / len(loader)
    f1_macro = f1_score(all_labels, all_preds, average="macro", zero_division=0)
    return {"loss": avg_loss, "f1_macro": f1_macro,
            "preds": all_preds, "labels": all_labels}


def backup_to_drive(src: Path, backup_dir: Path, epoch: int, val_f1: float):
    """Copy best checkpoint to Drive. Safe to call even if Drive is slow."""
    try:
        dest = backup_dir / f"epoch{epoch}_f1{val_f1:.4f}"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        print(f"  ✓ Backed up to Drive: {dest}")
    except Exception as e:
        print(f"  ⚠ Drive backup failed (training continues): {e}")


def main(resume: str | None = None, backup_dir: str | None = None):
    set_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n=== LinkGuard Model Training ===")
    print(f"Device: {device}")
    if device.type == "cuda":
        print(f"GPU: {torch.cuda.get_device_name(0)}")

    # ── Tokenizer ─────────────────────────────────────────────────────────────
    print(f"\nLoading tokenizer: {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    # ── Datasets ──────────────────────────────────────────────────────────────
    print("\nLoading datasets...")
    train_ds = URLDataset(PROCESSED_DIR / "train.parquet", tokenizer)
    val_ds   = URLDataset(PROCESSED_DIR / "val.parquet",   tokenizer)

    num_workers = 2
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True,
                              num_workers=num_workers, pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=BATCH_SIZE * 2, shuffle=False,
                              num_workers=num_workers, pin_memory=True)

    print(f"  Train: {len(train_ds):,} | Val: {len(val_ds):,}")

    # ── Model ─────────────────────────────────────────────────────────────────
    print(f"\nBuilding model (base: {BASE_MODEL})...")
    model = HybridURLClassifier()
    if resume:
        print(f"  Resuming from {resume}")
        model.load_state_dict(torch.load(resume, map_location="cpu"))
    model = model.to(device)
    print(f"  {count_params(model)}")

    # Freeze bottom 8 BERT layers for first 2 epochs
    model.freeze_bert_layers(num_layers_to_freeze=8)
    print("  BERT bottom-8 layers frozen for warm-up epochs 1-2")

    # ── Training setup ────────────────────────────────────────────────────────
    class_weights = get_class_weights(train_ds, device)
    print(f"  Class weights: {class_weights.tolist()}")
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    optimizer = make_optimizer(model)

    total_steps = (len(train_loader) // GRAD_ACCUM) * NUM_EPOCHS
    warmup_steps = int(total_steps * WARMUP_RATIO)
    scheduler = get_cosine_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_steps,
        num_training_steps=total_steps
    )

    scaler = torch.amp.GradScaler("cuda", enabled=(device.type == "cuda"))

    # ── Logging ───────────────────────────────────────────────────────────────
    log_path = MODEL_DIR / "training_log.csv"
    log_file = open(log_path, "w", newline="")
    log_writer = csv.writer(log_file)
    log_writer.writerow(["epoch", "step", "train_loss", "val_loss", "val_f1"])

    best_f1   = 0.0
    best_path = MODEL_DIR / "best_model"

    # ── Training loop ─────────────────────────────────────────────────────────
    global_step = 0
    for epoch in range(1, NUM_EPOCHS + 1):

        # Unfreeze all BERT layers after epoch 2
        if epoch == 3:
            model.unfreeze_all()
            # Rebuild optimizer so unfrozen params are included
            optimizer = make_optimizer(model)
            scheduler = get_cosine_schedule_with_warmup(
                optimizer, num_warmup_steps=0,
                num_training_steps=(len(train_loader) // GRAD_ACCUM) * (NUM_EPOCHS - 2)
            )
            print("  All BERT layers unfrozen for epochs 3+")

        model.train()
        epoch_loss = 0.0
        optimizer.zero_grad()

        bar = tqdm(train_loader, desc=f"Epoch {epoch}/{NUM_EPOCHS}", leave=True)
        for step, batch in enumerate(bar, 1):
            input_ids      = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            url_features   = batch["url_features"].to(device)
            labels         = batch["label"].to(device)

            with torch.amp.autocast("cuda", enabled=(device.type == "cuda")):
                logits = model(input_ids, attention_mask, url_features)
                loss   = criterion(logits, labels) / GRAD_ACCUM

            scaler.scale(loss).backward()

            if step % GRAD_ACCUM == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), MAX_GRAD_NORM)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()
                optimizer.zero_grad()
                global_step += 1

            epoch_loss += loss.item() * GRAD_ACCUM
            bar.set_postfix(loss=f"{loss.item() * GRAD_ACCUM:.4f}",
                            lr=f"{optimizer.param_groups[0]['lr']:.2e}")

        avg_train_loss = epoch_loss / len(train_loader)

        # Validate
        val_metrics = evaluate(model, val_loader, criterion, device)
        val_f1   = val_metrics["f1_macro"]
        val_loss = val_metrics["loss"]

        print(f"\n  Epoch {epoch}: train_loss={avg_train_loss:.4f} "
              f"val_loss={val_loss:.4f} val_f1={val_f1:.4f}")

        log_writer.writerow([epoch, global_step, avg_train_loss, val_loss, val_f1])
        log_file.flush()

        if val_f1 > best_f1:
            best_f1 = val_f1
            best_path.mkdir(exist_ok=True)
            torch.save(model.state_dict(), best_path / "model.pt")
            tokenizer.save_pretrained(best_path)
            print(f"  ✓ New best model saved (val_f1={best_f1:.4f})")
            if backup_dir:
                backup_to_drive(best_path, Path(backup_dir), epoch, best_f1)

    log_file.close()

    # ── Final report ──────────────────────────────────────────────────────────
    print(f"\n=== Training Complete ===")
    print(f"Best val F1: {best_f1:.4f}")
    print(f"Model saved: {best_path}")
    print(f"Log: {log_path}")
    print("\nNext: python train/evaluate.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", type=str, default=None,
                        help="Path to a model.pt checkpoint to resume from")
    parser.add_argument("--backup-dir", type=str, default=None,
                        help="Google Drive folder to back up best checkpoints (e.g. /content/drive/MyDrive/linkguard)")
    args = parser.parse_args()
    main(resume=args.resume, backup_dir=args.backup_dir)
