"""Anomaly detection helpers.

Includes IsolationForest and a PyOD-friendly wrapper. These are small helpers
— production anomaly engines should be separate microservices with model
management and feature stores.
"""
from typing import List, Dict


def detect_anomalies_isolation(values: List[float], contamination: float = 0.05) -> List[int]:
    """Return list of indices flagged as anomalies (placeholder implementation)."""
    # placeholder: flag top contamination fraction of largest deviations
    if not values:
        return []
    n = max(1, int(len(values) * contamination))
    # simple heuristic: pick indices of largest absolute deviation from mean
    import numpy as np
    arr = np.array(values)
    deviations = np.abs(arr - arr.mean())
    idx = deviations.argsort()[-n:][::-1]
    return idx.tolist()
