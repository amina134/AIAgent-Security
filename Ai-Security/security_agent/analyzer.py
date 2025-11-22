# security_agent/analyzer.py
import numpy as np
from .model_loader import embed
from .signatures import init_signatures
from .detectors import HeuristicDetectors
from .utils import cosine_sim

# seuils configurables
SIMILARITY_THRESHOLD = 0.75   # si cosine >= 0.75 => fortement similaire
SCORE_FROM_SIM = 60          # influence du match signature
SCORE_FROM_HEUR = 40         # influence heuristique

store = init_signatures()
SIGN_EMBS = store["embeddings"]
SIGN_TAGS = store["tags"]
SIGN_IDS = store["ids"]

class RequestAnalyzer:
    def __init__(self):
        pass

    def extract_text_features(self, request):
        """
        Extrait un texte résumé pour analyser : path, query params, small body snippet.
        On masque les PII avant d'envoyer au modèle.
        """
        parts = []
        parts.append(str(request.path))
        # query params
        try:
            q = dict(request.GET)
            parts.append(" ".join([f"{k}={v}" for k,v in q.items()]))
        except Exception:
            pass
        # small POST body (si JSON)
        try:
            body = request.body.decode("utf-8")[:1000]
            parts.append(body)
        except Exception:
            pass
        text = " || ".join([p for p in parts if p])
        return text

    def analyze(self, request):
        text = self.extract_text_features(request)
        # redaction simple — ici tu peux ajouter masque d'email, num etc.
        # compute embedding
        emb = embed(text)
        # normalize
        emb_norm = emb / (np.linalg.norm(emb) + 1e-12)
        # similarity vs signatures
        sims = cosine_sim(emb_norm, SIGN_EMBS)  # array len n_sign
        max_idx = int(np.argmax(sims))
        max_sim = float(sims[max_idx])

        report = {
            "text": text[:1000],
            "max_similarity": max_sim,
            "matched_signature": SIGN_IDS[max_idx],
            "matched_tag": SIGN_TAGS[max_idx],
            "heuristics": {}
        }

        # heuristics checks
        report["heuristics"]["sqli"] = HeuristicDetectors.check_sqli(text)
        report["heuristics"]["xss"] = HeuristicDetectors.check_xss(text)
        report["heuristics"]["path_trav"] = HeuristicDetectors.check_path_traversal(text)
        report["heuristics"]["ssrf"] = HeuristicDetectors.check_ssrf(text)

        # compute risk score
        score = 0.0
        if max_sim >= SIMILARITY_THRESHOLD:
            score += SCORE_FROM_SIM * max_sim  # scale par similarité
        # add heuristics weight
        heur_count = sum(1 for v in report["heuristics"].values() if v)
        score += SCORE_FROM_HEUR * min(heur_count, 1)  # si au moins 1 heur trigger

        # clamp 0-100
        score = max(0.0, min(100.0, score))
        report["risk_score"] = round(score, 2)
        return report
