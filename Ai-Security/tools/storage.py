import os
import json
from datetime import datetime
import numpy as np
from django.conf import settings

DATA_DIR = os.path.join(str(settings.BASE_DIR), "security_data")

TEXTS_PATH = os.path.join(DATA_DIR, "texts.json")
EMB_PATH = os.path.join(DATA_DIR, "embeddings.npy")
os.makedirs(DATA_DIR, exist_ok=True)

def save_suspicious_payload(raw_text: str, embedding: np.ndarray, metadata: dict = None):
    """Append a record (embedding + text) to a JSONL file and a .npy store for embeddings."""
    metadata = metadata or {}
    ts = datetime.utcnow().isoformat()

    # Save JSONL
    record = {"ts": ts, "text": raw_text, "meta": metadata}
    try:
        with open(os.path.join(DATA_DIR, "suspicious_payloads.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"Error saving JSONL: {e}")

    # Save embeddings
    emb_path = os.path.join(DATA_DIR, "embeddings.npy")
    try:
        if not os.path.exists(emb_path):
            np.save(emb_path, embedding.astype(np.float32))
        else:
            arr = np.load(emb_path)
            arr = np.vstack([arr, embedding.astype(np.float32)])
            np.save(emb_path, arr)
    except Exception as e:
        print(f"Error saving embedding: {e}")




def load_all_payloads():
    """
    Loads all stored suspicious payload texts from suspicious_payloads.jsonl.
    Returns a list of raw text strings.
    """
    file_path = os.path.join(DATA_DIR, "suspicious_payloads.jsonl")
    if not os.path.exists(file_path):
        return []

    texts = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line)
                texts.append(record.get("text", ""))
            except:
                continue
    return texts
