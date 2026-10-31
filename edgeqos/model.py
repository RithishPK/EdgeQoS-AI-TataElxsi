"""Dependency-free, bounded Random Forest training and JSON inference.

Demo distributions are synthetic; their validation accuracy says nothing about
real application recognition. Encrypted traffic can only suggest behavior.
"""
import collections
import csv
import json
import math
import random
from pathlib import Path
from . import boost
from .features import FEATURES_V2,FEATURES_V3,BEHAVIORS

FEATURES = ["mean_bytes", "std_bytes", "packets_per_second", "up_ratio", "udp", "duration"]
LABELS = ["realtime", "interactive", "best_effort", "bulk"]


class Forest:
    def __init__(self, data):
        if data.get("features") not in (FEATURES,FEATURES_V2,FEATURES_V3) or data.get("labels") not in (LABELS,BEHAVIORS):
            raise ValueError("Model feature/label schema mismatch")
        trees = data.get("trees", [])
        if not 1 <= len(trees) <= 64:
            raise ValueError("Invalid forest size")
        def validate(node, depth=0):
            if depth > 12 or not isinstance(node, dict):
                raise ValueError("Invalid tree depth/structure")
            if "p" in node:
                p = node["p"]
                if len(p) != len(data['labels']) or any(not math.isfinite(x) or x < 0 for x in p) or abs(sum(p)-1) > .001:
                    raise ValueError("Invalid leaf")
            else:
                if not isinstance(node.get("f"), int) or not 0 <= node["f"] < len(data['features']) or not math.isfinite(node["t"]):
                    raise ValueError("Invalid split")
                validate(node["l"], depth+1)
                validate(node["r"], depth+1)
        for tree in trees:
            validate(tree)
        self.data = data

    @classmethod
    def load(cls, path):
        if Path(path).stat().st_size > 2_000_000:
            raise ValueError("Model exceeds 2 MB limit")
        return cls(json.loads(Path(path).read_text()))

    def predict(self, values):
        if len(values) != len(self.data['features']) or any(not math.isfinite(v) for v in values):
            raise ValueError("Invalid feature vector")
        totals = [0.0] * len(self.data['labels'])
        for tree in self.data["trees"]:
            while "p" not in tree:
                tree = tree["l"] if values[tree["f"]] <= tree["t"] else tree["r"]
            for i, p in enumerate(tree["p"]):
                totals[i] += p
        winner = max(range(len(totals)), key=totals.__getitem__)
        return self.data['labels'][winner], totals[winner] / len(self.data["trees"])


def train(rows, seed=42, trees=24, depth=7, provenance="user-labelled",
          features=FEATURES, labels=LABELS):
    width, classes = len(features), len(labels)
    if not rows or any(y not in range(classes) or len(x) != width or any(not math.isfinite(v) for v in x) for x,y in rows):
        raise ValueError("Invalid training rows")
    rng = random.Random(seed)
    per_split = max(1, round(width ** .5))
    def build(samples, level):
        counts = collections.Counter(y for _, y in samples)
        leaf = {"p": [counts[i]/len(samples) for i in range(classes)]}
        if level >= depth or len(samples) < 16 or len(counts) == 1:
            return leaf
        best = None
        for feature in rng.sample(range(width), per_split):
            vals = sorted(set(x[feature] for x,_ in samples))
            if len(vals) < 2:
                continue
            candidates = [vals[min(len(vals)-2, int(len(vals)*q/9))] for q in range(1,9)]
            for threshold in candidates:
                left = [s for s in samples if s[0][feature] <= threshold]
                right = [s for s in samples if s[0][feature] > threshold]
                if min(len(left),len(right)) < 4:
                    continue
                score = 0
                for side in (left,right):
                    c = collections.Counter(y for _,y in side)
                    score += len(side) * (1-sum((v/len(side))**2 for v in c.values()))
                if best is None or score < best[0]:
                    best = (score, feature, threshold, left, right)
        if best is None:
            return leaf
        _, f,t,l,r = best
        return {"f": f, "t": t, "l": build(l,level+1), "r": build(r,level+1)}
    return Forest({"schema":1, "features":features, "labels":labels,
                   "provenance":provenance, "training_rows":len(rows), "seed":seed,
                   "trees":[build(rng.choices(rows,k=len(rows)),0) for _ in range(trees)]})


def load_model(path):
    """Load whichever ensemble kind the file declares; schema is self-describing."""
    if Path(path).stat().st_size > 2_000_000:
        raise ValueError("Model exceeds 2 MB limit")
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError("Model must be a JSON object")
    if data.get("kind") == boost.KIND:
        return boost.Booster(data)
    return Forest(data)


def synthetic(seed=17, n=1600):
    rng = random.Random(seed)
    # Overlap intentionally retained. These are behavioral examples, not app labels.
    profiles = [(220,110,65,.48,1,20), (430,260,14,.42,0,7),
                (780,440,40,.25,0,12), (1310,190,450,.07,0,40)]
    rows=[]
    for i in range(n):
        y=i%4
        p=profiles[y]
        x=[max(.001,rng.gauss(v, max(.03, v*.35))) for v in p]
        x[3]=min(1,x[3]); x[4]=float(rng.random() < (.90 if y==0 else .22))
        rows.append((x,y))
    rng.shuffle(rows)
    return rows


def read_csv(path):
    with open(path,newline="") as f:
        rows=[([float(r[k]) for k in FEATURES],LABELS.index(r["label"])) for r in csv.DictReader(f)]
    if len(rows) < 80:
        raise ValueError("At least 80 independently labelled flows required")
    return rows
