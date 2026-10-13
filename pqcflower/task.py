"""Crop data, farm partitions and a small softmax-regression model (NumPy only)."""

import os
from pathlib import Path

import numpy as np

# Flower copies the app before running it, so the data location comes from the environment.
DATA_CSV = Path(os.environ.get("PQC_DATA_DIR", Path(__file__).resolve().parent.parent / "data")) / "Crop_recommendation.csv"
FEATURES = ["Nitrogen", "phosphorus", "potassium", "temperature", "humidity", "ph", "rainfall"]
# Fixed agronomic ranges, so every farm scales its sensors the same way without sharing data.
FEATURE_MIN = np.array([0, 5, 5, 8, 14, 3.5, 20], dtype=np.float64)
FEATURE_MAX = np.array([140, 145, 205, 44, 100, 10, 300], dtype=np.float64)
SEED = 42

_cache: dict = {}


def _load():
    if "data" not in _cache:
        raw = np.genfromtxt(DATA_CSV, delimiter=",", dtype=str, skip_header=1)
        x = (raw[:, :7].astype(np.float64) - FEATURE_MIN) / (FEATURE_MAX - FEATURE_MIN)
        classes = sorted(set(raw[:, 7]))
        y = np.array([classes.index(c) for c in raw[:, 7]])
        _cache["data"] = (x, y, classes)
    return _cache["data"]


def num_classes() -> int:
    return len(_load()[2])


def _split():
    """20% held-out test set; the rest is the farms' private data."""
    if "split" not in _cache:
        x, y, _ = _load()
        idx = np.random.default_rng(SEED).permutation(len(y))
        n_test = len(y) // 5
        _cache["split"] = (idx[n_test:], idx[:n_test])
    return _cache["split"]


def load_test():
    x, y, _ = _load()
    _, test_idx = _split()
    return x[test_idx], y[test_idx]


def load_farm(partition_id: int, num_partitions: int, alpha: float = 0.5):
    """Non-IID farm split: each farm grows a different mix of crops (Dirichlet over labels)."""
    x, y, _ = _load()
    train_idx, _ = _split()
    rng = np.random.default_rng(SEED)
    farms = [[] for _ in range(num_partitions)]
    for c in range(num_classes()):
        idx_c = train_idx[y[train_idx] == c]
        rng.shuffle(idx_c)
        cuts = (np.cumsum(rng.dirichlet([alpha] * num_partitions)) * len(idx_c)).astype(int)[:-1]
        for farm, part in zip(farms, np.split(idx_c, cuts)):
            farm.extend(part)
    mine = np.array(farms[partition_id])
    rng.shuffle(mine)
    n_val = max(1, len(mine) // 5)
    return (x[mine[n_val:]], y[mine[n_val:]]), (x[mine[:n_val]], y[mine[:n_val]])


def init_model():
    rng = np.random.default_rng(SEED)
    return [rng.normal(0, 0.01, (len(FEATURES), num_classes())), np.zeros(num_classes())]


def _softmax(z):
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def train(model, x, y, epochs: int, lr: float, batch_size: int = 32):
    w, b = (m.copy() for m in model)
    rng = np.random.default_rng()
    onehot = np.eye(num_classes())[y]
    for _ in range(epochs):
        order = rng.permutation(len(y))
        for s in range(0, len(y), batch_size):
            batch = order[s : s + batch_size]
            p = _softmax(x[batch] @ w + b)
            grad = (p - onehot[batch]) / len(batch)
            w -= lr * x[batch].T @ grad
            b -= lr * grad.sum(axis=0)
    return [w, b]


def evaluate(model, x, y):
    w, b = model
    p = _softmax(x @ w + b)
    loss = float(-np.log(p[np.arange(len(y)), y] + 1e-12).mean())
    acc = float((p.argmax(axis=1) == y).mean())
    return loss, acc
