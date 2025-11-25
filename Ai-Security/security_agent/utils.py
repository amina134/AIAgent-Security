import base64
import urllib.parse
import binascii
from .models import SuspiciousPayload
from sentence_transformers import SentenceTransformer
import json
import numpy as np
import faiss
def decode_obfuscated_text(text):
    decoded_texts = [text]

    # URL decode
    try:
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            decoded_texts.append(url_decoded)
    except:
        pass

    # Base64 decode
    try:
        b64_decoded = base64.b64decode(text).decode('utf-8')
        decoded_texts.append(b64_decoded)
    except:
        pass

    # Hex decode
    try:
        hex_decoded = binascii.unhexlify(text.replace("\\x","")).decode('utf-8')
        decoded_texts.append(hex_decoded)
    except:
        pass

    return decoded_texts



model = SentenceTransformer("all-MiniLM-L6-v2")
def store_new_malicious_payload(raw_text, threat_type="Unknown"):
    vector = model.encode([raw_text]).tolist()  # convert to list
    payload = SuspiciousPayload.objects.create(
        raw_text=raw_text,
        threat_type=threat_type,
        vector=json.dumps(vector),
        confirmed=True
    )
    payload.save()

def rebuild_faiss_index():
    payloads = SuspiciousPayload.objects.filter(confirmed=True)
    if not payloads.exists():
        return None

    vectors = [json.loads(p.vector) for p in payloads]
    vectors = np.array(vectors).astype("float32")
    dimension = vectors.shape[1]
    index = faiss.IndexFlatIP(dimension)
    faiss.normalize_L2(vectors)
    index.add(vectors)
    return index