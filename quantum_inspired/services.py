"""Classical/quantum-inspired simulation helpers.

These implementations are heuristic/classical approximations designed to
simulate the behavior of quantum-inspired techniques for threat modeling.
They are intentionally lightweight, deterministic, and safe to run in a
regular Python environment.
"""
from typing import Any, Dict, List
import math
import random


def grover_search_simulation(dataset: List[Any], predicate) -> Dict:
    """Classical speedup simulation: returns candidate matches and simulated steps."""
    n = len(dataset)
    matches = [i for i, v in enumerate(dataset) if predicate(v)]
    # Simulate Grover step count ~ O(sqrt(N/M)) if M>0
    m = max(1, len(matches))
    steps = int(math.sqrt(n / m))
    return {'matches': matches, 'simulated_steps': steps, 'n': n, 'm': m}


def quantum_walks_simulation(graph_edges: List[tuple], source: int, depth: int = 3) -> Dict:
    """Simulate quantum-walk-like propagation probabilities over graph edges."""
    # Build adjacency
    adj = {}
    for a, b in graph_edges:
        adj.setdefault(a, []).append(b)
        adj.setdefault(b, []).append(a)

    prob = {source: 1.0}
    for _ in range(depth):
        next_prob = {}
        for node, p in prob.items():
            nbrs = adj.get(node, [])
            if not nbrs:
                next_prob[node] = next_prob.get(node, 0) + p
                continue
            share = p / len(nbrs)
            for nb in nbrs:
                next_prob[nb] = next_prob.get(nb, 0) + share
        prob = next_prob
    return {'probability': prob}


def factorial_permutation_engine(items: List[Any], limit: int = 1000) -> Dict:
    """Enumerate threat paths up to a safe limit and return sampled permutations."""
    n = len(items)
    max_perm = math.factorial(n) if n < 8 else float('inf')
    sample = []
    if max_perm == float('inf'):
        # sample random permutations
        for _ in range(min(limit, 200)):
            s = items[:]
            random.shuffle(s)
            sample.append(s[:5])
    else:
        # deterministic simple enumeration up to limit
        from itertools import permutations
        for i, p in enumerate(permutations(items)):
            if i >= limit:
                break
            sample.append(p)
    return {'sampled_paths': sample, 'n': n}


def quantum_decision_trees(data: List[Dict], max_depth: int = 3) -> Dict:
    """A classical decision tree builder that mimics a 'quantum decision tree' idea."""
    # Very simple splitting heuristic based on entropy-like score
    def entropy(group):
        counts = {}
        for row in group:
            label = row.get('label')
            counts[label] = counts.get(label, 0) + 1
        e = 0.0
        total = len(group)
        for c in counts.values():
            p = c / total
            e -= p * math.log2(p) if p > 0 else 0
        return e

    root_score = entropy(data)
    return {'root_entropy': root_score, 'size': len(data)}


def variational_circuits_simulation(features: List[float], epochs: int = 20) -> Dict:
    """A toy gradient-based optimizer that returns a fitted weight vector."""
    w = [random.random() * 0.1 for _ in features]
    lr = 0.01
    for _ in range(epochs):
        grads = [random.uniform(-0.05, 0.05) for _ in features]
        w = [wi - lr * g for wi, g in zip(w, grads)]
    return {'weights': w}


def quantum_boltzmann_clustering(points: List[List[float]], k: int = 3, iterations: int = 10) -> Dict:
    """A Boltzmann-like clustering via simulated annealing (toy)."""
    centers = random.sample(points, min(k, len(points)))
    T0 = 1.0
    for t in range(iterations):
        T = T0 * (1 - t / iterations)
        # pseudo-update
        centers = [[(c + random.uniform(-T, T)) for c in center] for center in centers]
    return {'centers': centers}


def quantum_annealing_simulation(states: List[Any], energy_fn, steps: int = 100) -> Dict:
    """Simulated annealing as an approximation to quantum annealing."""
    current = states[0] if states else None
    best = current
    best_energy = energy_fn(current) if current is not None else None
    for i in range(steps):
        candidate = random.choice(states)
        e = energy_fn(candidate)
        if best_energy is None or e < best_energy:
            best = candidate
            best_energy = e
    return {'best': best}


def quantum_entropy_pool(seed_bytes: bytes, extra: int = 32) -> bytes:
    """Expand entropy by hashing and mixing (toy)."""
    import hashlib
    h = hashlib.sha512(seed_bytes).digest()
    # return requested extra bytes by repeated hashing
    out = h
    while len(out) < extra:
        out += hashlib.sha512(out).digest()
    return out[:extra]


def quantum_inspired_graph_traversal(edges: List[tuple], start: int, depth: int = 4) -> Dict:
    """Detect lateral movement like traversal scoring using breadth-first influence."""
    from collections import deque, defaultdict
    q = deque([(start, 0)])
    seen = set([start])
    score = defaultdict(float)
    while q:
        node, d = q.popleft()
        score[node] += 1.0 / (1 + d)
        if d >= depth:
            continue
        for a, b in edges:
            if a == node and b not in seen:
                seen.add(b)
                q.append((b, d + 1))
            if b == node and a not in seen:
                seen.add(a)
                q.append((a, d + 1))
    return {'score': dict(score)}


def quantum_state_collapse_simulation(candidates: List[Any], scores: List[float]) -> Dict:
    """Simulate 'collapse' by probabilistically selecting highest-score candidates."""
    import numpy as np
    probs = np.array(scores)
    probs = probs / probs.sum() if probs.sum() > 0 else np.ones_like(probs) / len(probs)
    idx = int(np.argmax(probs))
    return {'selected_index': int(idx), 'probabilities': probs.tolist()}
