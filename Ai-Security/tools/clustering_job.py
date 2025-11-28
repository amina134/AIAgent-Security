import numpy as np
from sklearn.cluster import MiniBatchKMeans
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from django.conf import settings
import json
import os

DATA_DIR = Path(settings.BASE_DIR) / "security_data"
EMB_PATH = DATA_DIR / "embeddings.npy"
CLUSTER_META = DATA_DIR / "cluster_meta.json"
CENTROIDS_PATH = DATA_DIR / "cluster_centroids.npy"

def run_clustering(n_clusters=20):
    if not EMB_PATH.exists():
        print("No embeddings found")
        return

    X = np.load(EMB_PATH).astype(np.float32)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    kmeans = MiniBatchKMeans(n_clusters=n_clusters, batch_size=1024, random_state=42)
    labels = kmeans.fit_predict(Xs)
    centroids = kmeans.cluster_centers_

    # Simple cluster risk
    # Simple cluster risk
    cluster_counts = {}
    for lab in labels:
        cluster_counts[int(lab)] = cluster_counts.get(int(lab), 0) + 1  # convert lab to Python int

    max_cnt = max(cluster_counts.values())
 # Save cluster meta
    cluster_meta = {}
    for c, cnt in cluster_counts.items():
        cluster_meta[str(c)] = {"count": int(cnt), "risk": round(0.1 + 0.8 * (cnt / max_cnt), 3)}

    np.save(CENTROIDS_PATH, centroids.astype(np.float32))
    with open(CLUSTER_META, "w", encoding="utf-8") as f:
        json.dump(cluster_meta, f, indent=2)
