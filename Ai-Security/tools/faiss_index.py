import faiss
import numpy as np
from pathlib import Path
from django.conf import settings

CENTROIDS_PATH = Path(settings.BASE_DIR) / "security_data" / "cluster_centroids.npy"
CLUSTER_INDEX_PATH = Path(settings.BASE_DIR) / "security_data" / "cluster_index.faiss"

def build_cluster_index():
    centroids = np.load(CENTROIDS_PATH).astype(np.float32)
    d = centroids.shape[1]
    idx = faiss.IndexFlatIP(d)
    faiss.normalize_L2(centroids)
    idx.add(centroids)
    faiss.write_index(idx, str(CLUSTER_INDEX_PATH))
    return idx

def load_cluster_index():
    if not CLUSTER_INDEX_PATH.exists():
        return build_cluster_index()
    return faiss.read_index(str(CLUSTER_INDEX_PATH))
