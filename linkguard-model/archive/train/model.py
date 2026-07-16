"""
model.py — Hybrid URL Safety Classifier.

Architecture:
                                     ┌─────────────────────────────┐
  URL string → tokenizer → SecureBERT│ → CLS token (hidden_size)   │
                                     └──────────────┬──────────────┘
                                                    │
  URL string → feature extractor → 50 features     │
                                   → MLP → 64       │
                                                    │
                               torch.cat([CLS, 64]) │
                                   ↓
                          Classifier head → 3 classes
                          (safe / suspicious / dangerous)
"""

import sys
from pathlib import Path

import torch
import torch.nn as nn
from transformers import AutoModel, AutoConfig

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import BASE_MODEL, NUM_URL_FEATURES, NUM_LABELS, DROPOUT


class URLFeatureMLP(nn.Module):
    """Processes the 50-dim hand-crafted URL features."""
    def __init__(self, input_dim: int = NUM_URL_FEATURES,
                 hidden_dim: int = 128, output_dim: int = 64,
                 dropout: float = DROPOUT):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, output_dim),
            nn.LayerNorm(output_dim),
            nn.GELU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class HybridURLClassifier(nn.Module):
    """
    SecureBERT + URL feature MLP → 3-class URL safety classifier.

    Forward inputs:
        input_ids      (B, seq_len)  LongTensor
        attention_mask (B, seq_len)  LongTensor
        url_features   (B, 50)       FloatTensor

    Returns:
        logits         (B, 3)        FloatTensor (not softmaxed)
    """

    def __init__(self,
                 base_model: str = BASE_MODEL,
                 num_url_features: int = NUM_URL_FEATURES,
                 num_labels: int = NUM_LABELS,
                 dropout: float = DROPOUT):
        super().__init__()

        self.bert = AutoModel.from_pretrained(base_model, attn_implementation="eager")
        hidden_size = self.bert.config.hidden_size  # 768 for BERT-base

        self.feature_branch = URLFeatureMLP(
            input_dim=num_url_features, output_dim=64, dropout=dropout
        )

        combined_dim = hidden_size + 64

        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(combined_dim, 256),
            nn.LayerNorm(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, num_labels),
        )

    def forward(self,
                input_ids: torch.Tensor,
                attention_mask: torch.Tensor,
                url_features: torch.Tensor) -> torch.Tensor:

        # SecureBERT branch
        outputs  = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        cls_out  = outputs.last_hidden_state[:, 0, :]  # (B, 768)

        # Feature branch
        feat_out = self.feature_branch(url_features)   # (B, 64)

        # Combine and classify
        combined = torch.cat([cls_out, feat_out], dim=1)  # (B, 832)
        logits   = self.classifier(combined)               # (B, 3)
        return logits

    def freeze_bert_layers(self, num_layers_to_freeze: int = 8):
        """
        Freeze the bottom N transformer layers for early-epoch training.
        Helps stabilize fine-tuning when dataset is small.
        Unfreeze all before final epochs.
        """
        encoder_layers = self.bert.encoder.layer
        for i, layer in enumerate(encoder_layers):
            if i < num_layers_to_freeze:
                for param in layer.parameters():
                    param.requires_grad = False

    def unfreeze_all(self):
        for param in self.parameters():
            param.requires_grad = True


def count_params(model: nn.Module) -> str:
    total     = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return f"Total: {total/1e6:.1f}M | Trainable: {trainable/1e6:.1f}M"


if __name__ == "__main__":
    import sys
    print("Loading model (this downloads SecureBERT on first run ~500MB)...")
    model = HybridURLClassifier()
    print(f"Parameters — {count_params(model)}")

    # Sanity forward pass
    B = 4
    input_ids      = torch.randint(0, 1000, (B, 64))
    attention_mask = torch.ones(B, 64, dtype=torch.long)
    url_features   = torch.randn(B, NUM_URL_FEATURES)

    logits = model(input_ids, attention_mask, url_features)
    print(f"Output shape: {logits.shape}")  # (4, 3)
    print(f"Probs: {torch.softmax(logits, dim=-1).detach()}")
    print("✓ Model forward pass OK")
