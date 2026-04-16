"""
Central configuration for LinkGuard URL Safety Classifier.
All paths are relative to the linkguard-model/ directory.
"""
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).parent
RAW_DIR       = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
MODEL_DIR     = ROOT / "model_output"
ONNX_DIR      = ROOT / "model_output" / "onnx"

RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)
ONNX_DIR.mkdir(parents=True, exist_ok=True)

# ── Data sources (automated downloads) ────────────────────────────────────────
URLHAUS_URL    = "https://urlhaus.abuse.ch/downloads/text_recent/"
OPENPHISH_URL  = "https://openphish.com/feed.txt"
THREATFOX_URL  = "https://threatfox-api.abuse.ch/api/v1/"
PHISHSTATS_URL = "https://phishstats.info/phish_score.csv"
TRANCO_URL     = "https://tranco-list.eu/top-1m.csv.zip"

# ── Labels ────────────────────────────────────────────────────────────────────
LABEL2ID = {"safe": 0, "suspicious": 1, "dangerous": 2}
ID2LABEL  = {0: "safe", 1: "suspicious", 2: "dangerous"}
NUM_LABELS = 3

# ── Model ─────────────────────────────────────────────────────────────────────
BASE_MODEL     = "ehsanaghaei/SecureBERT"   # cybersecurity-aware BERT
MAX_SEQ_LEN    = 128                          # URLs rarely exceed 128 tokens
NUM_URL_FEATURES = 50                         # hand-crafted structural features
DROPOUT        = 0.3

# ── Training ──────────────────────────────────────────────────────────────────
BATCH_SIZE     = 32
GRAD_ACCUM     = 2                            # effective batch = 64
LEARNING_RATE  = 2e-5
BERT_LR        = 1e-5                         # lower LR for pre-trained layers
NUM_EPOCHS     = 4
WARMUP_RATIO   = 0.06
WEIGHT_DECAY   = 0.01
MAX_GRAD_NORM  = 1.0
SEED           = 42

# ── Dataset splits ────────────────────────────────────────────────────────────
TRAIN_RATIO = 0.80
VAL_RATIO   = 0.10
TEST_RATIO  = 0.10

# Cap per class to keep training manageable on a single GPU (None = no cap)
MAX_SAFE_SAMPLES      = 300_000
MAX_DANGEROUS_SAMPLES = 300_000
MAX_SUSPICIOUS_SAMPLES = 50_000

# ── HuggingFace ────────────────────────────────────────────────────────────────
HF_REPO  = "linkguard/url-safety-classifier"   # your HF repo (update before push)
HF_SPACE = ""                                   # fill in after deploying Spaces app

# ── Inference ─────────────────────────────────────────────────────────────────
CONFIDENCE_THRESHOLD = 0.90    # below this → fall through to VirusTotal
