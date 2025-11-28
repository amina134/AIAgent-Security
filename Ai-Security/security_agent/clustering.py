import numpy as np
from sklearn.cluster import DBSCAN
import pickle
import os

CLUSTER_FILE = "security_agent/clusters/cluster_labels.pkl"

class ClusterManager:
    def __init__(self):
        self.labels = []
        self.vectors = []

        # Load old clusters if they exist
        if os.path.exists(CLUSTER_FILE):
            with open(CLUSTER_FILE, "rb") as f:
                data = pickle.load(f)
                self.vectors = data.get("vectors", [])
                self.labels = data.get("labels", [])

    def add_vector(self, vector):
        """Add new attack vector (embedding)."""
        self.vectors.append(vector)

    def update_clusters(self):
        """Recompute clusters using DBSCAN."""
        if len(self.vectors) < 5:
            return  # need at least a few samples

        clustering = DBSCAN(eps=1.2, min_samples=2).fit(self.vectors)
        self.labels = clustering.labels_

        # Save results
        with open(CLUSTER_FILE, "wb") as f:
            pickle.dump({
                "vectors": self.vectors,
                "labels": self.labels
            }, f)

    def get_cluster_risk(self, index):
        """Return risk score of the cluster."""
        label = self.labels[index]

        # -1 means "new/unknown cluster" → VERY risky
        if label == -1:
            return 1.0  

        # normal clusters → medium risk
        return 0.5
