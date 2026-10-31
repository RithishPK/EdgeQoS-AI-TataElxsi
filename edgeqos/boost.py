"""Dependency-free multiclass gradient-boosted trees: histogram splits, Newton leaves.

Chosen over the random forest for this workload because the behaviors it has to
separate are not separated by any single feature. Streaming and bulk are both
MTU-sized TCP downloads; only the burst structure (std_iat, packets_per_second)
tells them apart, and boosting spends successive rounds on exactly the residual
cases a bagged forest averages away.

The cost is calibration: boosting pushes margins towards 0/1, so the softmax
probability is confident by construction and cannot be read as an accuracy.
Confidence here means margin, and the operating threshold is set from the
held-out report, not assumed.

Same defensive posture as model.Forest: JSON only (never pickle), every field
bounded and re-validated on load, so a corrupted or hostile model file is a
load-time error rather than kernel-level misclassification.
"""
import bisect
import collections
import json
import math
import random
from pathlib import Path

from .features import BEHAVIORS, FEATURES_V2, FEATURES_V3

KIND = "gradient-boosted-trees"
MAX_ROUNDS = 200
MAX_DEPTH = 6
LEAF_CLAMP = 4.0


def softmax(scores):
    top = max(scores)
    exps = [math.exp(s - top) for s in scores]
    total = sum(exps)
    return [e / total for e in exps]


class Booster:
    """Validated, bounded inference over a serialized boosted ensemble."""

    def __init__(self, data):
        if data.get("kind") != KIND:
            raise ValueError("Not a gradient-boosted model")
        features, labels = data.get("features"), data.get("labels")
        if features not in (FEATURES_V2, FEATURES_V3) or labels not in (BEHAVIORS,):
            raise ValueError("Model feature/label schema mismatch")
        rounds = data.get("rounds", [])
        if not 1 <= len(rounds) <= MAX_ROUNDS:
            raise ValueError("Invalid ensemble size")
        rate = data.get("learning_rate")
        if not isinstance(rate, (int, float)) or not 0 < rate <= 1:
            raise ValueError("Invalid learning rate")
        base = data.get("base")
        if not isinstance(base, list) or len(base) != len(labels) or \
                any(not math.isfinite(b) or abs(b) > 20 for b in base):
            raise ValueError("Invalid base scores")

        def validate(node, depth=0):
            if depth > MAX_DEPTH or not isinstance(node, dict):
                raise ValueError("Invalid tree depth/structure")
            if "v" in node:
                if not math.isfinite(node["v"]) or abs(node["v"]) > LEAF_CLAMP + 1e-9:
                    raise ValueError("Invalid leaf value")
                return
            if not isinstance(node.get("f"), int) or not 0 <= node["f"] < len(features) \
                    or not math.isfinite(node["t"]):
                raise ValueError("Invalid split")
            validate(node["l"], depth + 1)
            validate(node["r"], depth + 1)

        for group in rounds:
            if not isinstance(group, list) or len(group) != len(labels):
                raise ValueError("Round must hold one tree per label")
            for tree in group:
                validate(tree)
        self.data = data

    @classmethod
    def load(cls, path):
        if Path(path).stat().st_size > 2_000_000:
            raise ValueError("Model exceeds 2 MB limit")
        return cls(json.loads(Path(path).read_text()))

    def margins(self, values):
        if len(values) != len(self.data["features"]) or any(not math.isfinite(v) for v in values):
            raise ValueError("Invalid feature vector")
        rate = self.data["learning_rate"]
        scores = list(self.data["base"])
        for group in self.data["rounds"]:
            for index, tree in enumerate(group):
                while "v" not in tree:
                    tree = tree["l"] if values[tree["f"]] <= tree["t"] else tree["r"]
                scores[index] += rate * tree["v"]
        return scores

    def predict(self, values):
        probabilities = softmax(self.margins(values))
        winner = max(range(len(probabilities)), key=probabilities.__getitem__)
        return self.data["labels"][winner], probabilities[winner]


def quantiles(rows, width, count=16):
    """Global split candidates per feature; computed once, reused at every node."""
    bounds = []
    for feature in range(width):
        values = sorted({x[feature] for x, _ in rows})
        if len(values) < 2:
            bounds.append([])
            continue
        picks = {values[min(len(values) - 2, int(len(values) * (q + 1) / count))]
                 for q in range(count - 1)}
        bounds.append(sorted(picks))
    return bounds


def train(rows, labels=BEHAVIORS, features=FEATURES_V2, rounds=60, depth=4,
          rate=.25, reg=1.0, min_samples=12, seed=42, provenance="synthetic-behavioral",
          feature_fraction=.75):
    """Fit the ensemble. Bounded rounds/depth keep Pi-class inference predictable."""
    width = len(features)
    classes = len(labels)
    if not rows or any(y not in range(classes) or len(x) != width or
                       any(not math.isfinite(v) for v in x) for x, y in rows):
        raise ValueError("Invalid training rows")
    if not 1 <= rounds <= MAX_ROUNDS or not 1 <= depth <= MAX_DEPTH:
        raise ValueError("Ensemble size outside supported bounds")

    rng = random.Random(seed)
    bounds = quantiles(rows, width)
    # Pre-binning makes each split a histogram scan instead of a re-sort.
    binned = [[bisect.bisect_left(bounds[f], x[f]) for f in range(width)] for x, _ in rows]
    sampled = max(1, int(round(width * feature_fraction)))

    counts = collections.Counter(y for _, y in rows)
    base = [math.log(max(1, counts[k]) / len(rows)) for k in range(classes)]
    offset = sum(base) / classes
    base = [b - offset for b in base]
    scores = [list(base) for _ in rows]

    def build(indices, grad, hess, level):
        total_g = sum(grad[i] for i in indices)
        total_h = sum(hess[i] for i in indices)
        leaf = {"v": max(-LEAF_CLAMP, min(LEAF_CLAMP, -total_g / (total_h + reg)))}
        if level >= depth or len(indices) < min_samples * 2 or total_h < 1e-6:
            return leaf
        best = None
        for feature in rng.sample(range(width), sampled):
            edges = bounds[feature]
            if not edges:
                continue
            slots = len(edges) + 1
            hist_g = [0.0] * slots
            hist_h = [0.0] * slots
            hist_n = [0] * slots
            for i in indices:
                slot = binned[i][feature]
                hist_g[slot] += grad[i]
                hist_h[slot] += hess[i]
                hist_n[slot] += 1
            parent = total_g * total_g / (total_h + reg)
            left_g = left_h = 0.0
            left_n = 0
            for slot in range(slots - 1):
                left_g += hist_g[slot]
                left_h += hist_h[slot]
                left_n += hist_n[slot]
                right_n = len(indices) - left_n
                if left_n < min_samples or right_n < min_samples:
                    continue
                right_g, right_h = total_g - left_g, total_h - left_h
                gain = (left_g * left_g / (left_h + reg)
                        + right_g * right_g / (right_h + reg) - parent)
                if gain > 1e-6 and (best is None or gain > best[0]):
                    best = (gain, feature, edges[slot], slot)
        if best is None:
            return leaf
        _gain, feature, threshold, slot = best
        left = [i for i in indices if binned[i][feature] <= slot]
        right = [i for i in indices if binned[i][feature] > slot]
        return {"f": feature, "t": threshold,
                "l": build(left, grad, hess, level + 1),
                "r": build(right, grad, hess, level + 1)}

    all_rows = list(range(len(rows)))
    ensemble = []
    for _ in range(rounds):
        probabilities = [softmax(s) for s in scores]
        group = []
        for k in range(classes):
            grad = [probabilities[i][k] - (1.0 if rows[i][1] == k else 0.0) for i in all_rows]
            hess = [max(1e-6, probabilities[i][k] * (1 - probabilities[i][k])) for i in all_rows]
            tree = build(all_rows, grad, hess, 0)
            group.append(tree)
            for i in all_rows:
                node = tree
                # Walk on raw values, exactly as Booster.predict does.
                while "v" not in node:
                    node = node["l"] if rows[i][0][node["f"]] <= node["t"] else node["r"]
                scores[i][k] += rate * node["v"]
        ensemble.append(group)
    return Booster({"schema": 2, "kind": KIND, "features": features, "labels": labels,
                    "provenance": provenance, "training_rows": len(rows), "seed": seed,
                    "learning_rate": rate, "depth": depth, "regularization": reg,
                    "base": base, "rounds": ensemble})
