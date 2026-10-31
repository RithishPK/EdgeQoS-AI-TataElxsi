#!/usr/bin/env python3
"""Train the in-home Random Forest from labelled captures (runs on the Pi, pure Python).

    python3 tools/train_home_model.py data/labelled/*.jsonl -o models/live-behavior-forest.json
"""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from edgeqos.model import train
from edgeqos.features import FEATURES_V2

LABELS = ["gaming", "streaming", "interactive", "bulk", "realtime"]

ap = argparse.ArgumentParser()
ap.add_argument("files", nargs="+")
ap.add_argument("-o", "--out", required=True)
ap.add_argument("--trees", type=int, default=64)
ap.add_argument("--depth", type=int, default=10)
a = ap.parse_args()

rows = []
for f in a.files:
    for line in open(f):
        r = json.loads(line)
        rows.append((r["features"], LABELS.index(r["label"])))
forest = train(rows, seed=42, trees=a.trees, depth=a.depth, provenance="edgeqos-live-labelled",
               features=FEATURES_V2, labels=LABELS)
forest.data["window_seconds"] = 10.0
json.dump(forest.data, open(a.out, "w"))
print("trained on %d windows -> %s" % (len(rows), a.out))
