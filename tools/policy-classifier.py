#!/usr/bin/env python3
"""A deterministic behavioural classifier, evaluated on this network's own traffic.

Why this rather than a bigger model: measured today, the deployed 256-tree forest
called a genuine 35 Mb/s download `streaming` in 70 of 78 windows, and predicted
`gaming` zero times across 359 mobile-game windows. The cause is not capacity. A 4K
stream fetches a chunk then pauses; a download never pauses. Over a 10-second
window those are near-identical in mean packet size, rate and direction - and
none of the twelve FEATURES_V2 encodes the pause.

But the signal is partly recoverable from features already collected:

    std_iat / mean_iat   (coefficient of variation of inter-arrival time)

Measured live: steady mobile-game control traffic CV ~1.2, bursty chunked CDN
delivery CV ~5.1. The forest holds both numbers but cannot easily use their
ratio, because trees split on axis-aligned thresholds. Supplying the ratio makes
the distinction learnable - and usable by explicit rules in the meantime.

The rules below implement the operator's stated policy directly:

    gaming / voice      low rate, small packets, steady, bidirectional -> Voice
    video call          moderate rate, steady-ish, bidirectional       -> Video
    video streaming     high rate, large packets, BURSTY, inbound      -> Video
    bulk transfer       high rate, large packets, CONTINUOUS, inbound  -> Bulk
    everything else     unknown                                        -> Best Effort

No payload, no ports, no IP identity: sizes, timing and direction only. Every
decision carries the reason that produced it, so it can be argued with.
"""
import json
import sys
from pathlib import Path

FEATURES = ['mean_bytes', 'std_bytes', 'packets_per_second', 'up_ratio', 'udp',
            'duration', 'mean_iat', 'std_iat', 'small_ratio', 'large_ratio',
            'bytes_per_second', 'direction_switch_ratio']
IDX = {name: i for i, name in enumerate(FEATURES)}

# Thresholds are deliberately round numbers chosen from the physics of each
# class, not fitted to this sample: a game cannot need megabits, a 4K stream
# cannot fit in hundreds of kilobits, and a chunked stream must pause.
RATE_INTERACTIVE = 2.0      # Mb/s: above this it is not a game or a voice call
RATE_HEAVY = 5.0            # Mb/s: below this it is not a 4K stream or a download
SMALL_PACKET = 500          # bytes mean: control traffic is small
LARGE_PACKET = 900          # bytes mean: bulk/video fill the MTU
BURSTY_CV = 2.5             # std_iat/mean_iat above this means it pauses
BIDIRECTIONAL = 0.15        # up_ratio: a call/game talks back; a download does not


def classify(vector):
    """Return (queue, reason). Queue names match QUEUE_FOR_BEHAVIOR's outputs."""
    f = {name: float(vector[IDX[name]]) for name in FEATURES}
    rate = f['bytes_per_second'] * 8 / 1e6
    mean_iat = f['mean_iat'] or 1e-9
    cv = f['std_iat'] / mean_iat
    mean_bytes = f['mean_bytes']
    up = f['up_ratio']
    udp = f['udp'] >= 0.5

    # Latency-critical: small packets, low rate, talks in both directions.
    if rate <= RATE_INTERACTIVE and mean_bytes <= SMALL_PACKET and up >= BIDIRECTIONAL:
        return "realtime", ("%.2f Mb/s, %.0f B packets, %.0f%% upstream: "
                            "small bidirectional traffic needs promptness, not bandwidth"
                            % (rate, mean_bytes, 100 * up))

    # Heavy inbound traffic: the burst test decides whether it is paced media or
    # an unpaced transfer. This is the distinction the forest cannot see.
    if rate >= RATE_HEAVY and mean_bytes >= LARGE_PACKET and up < BIDIRECTIONAL:
        if cv >= BURSTY_CV:
            return "interactive", ("%.1f Mb/s, %.0f B packets, CV %.1f: paced in bursts, "
                                   "so media that needs throughput but tolerates delay"
                                   % (rate, mean_bytes, cv))
        return "bulk", ("%.1f Mb/s, %.0f B packets, CV %.1f: continuous unpaced transfer, "
                        "no deadline" % (rate, mean_bytes, cv))

    # Moderate, steady, bidirectional: a video call behaves like this.
    if rate > RATE_INTERACTIVE and rate < RATE_HEAVY and up >= BIDIRECTIONAL and udp:
        return "interactive", ("%.1f Mb/s, %.0f%% upstream, UDP: sustained two-way media"
                               % (rate, 100 * up))

    return "best_effort", ("%.2f Mb/s, %.0f B packets, CV %.1f, %.0f%% upstream: "
                           "no rule fits confidently" % (rate, mean_bytes, cv, 100 * up))


# What each recorded session actually was, so the evaluation is against truth
# rather than against the model's own opinion.
TRUTH = {
    "bulk": {"realtime": False, "expect": "bulk",
             "note": "single-stream 35 Mb/s HTTPS download"},
    "gaming": {"realtime": True, "expect": "realtime",
               "note": "mobile game; UDP control is realtime, TCP asset fetches are not"},
}


def evaluate(paths):
    overall = {}
    for path in paths:
        rows = [json.loads(line) for line in open(path)]
        if not rows:
            continue
        label = rows[0]["label"]
        name = Path(path).name
        counts, model_counts = {}, {}
        udp_counts = {}
        for row in rows:
            queue, _reason = classify(row["features"])
            counts[queue] = counts.get(queue, 0) + 1
            model_counts[row.get("model_said")] = model_counts.get(row.get("model_said"), 0) + 1
            if row.get("protocol") == "UDP":
                udp_counts[queue] = udp_counts.get(queue, 0) + 1
        print("%s  (%s, %d windows)" % (name, label, len(rows)))
        print("    rules say : %s" % counts)
        print("    model said: %s" % model_counts)
        if udp_counts:
            print("    rules, UDP flows only: %s" % udp_counts)
        print()
        overall[name] = (label, counts, model_counts)
    return overall


def examples(paths, n=4):
    print("=== worked examples, with the reasoning ===")
    for path in paths:
        rows = [json.loads(line) for line in open(path)]
        rows.sort(key=lambda r: -(r.get("observed_rate_mbit") or 0))
        print("-- %s --" % Path(path).name)
        for row in rows[:n]:
            queue, reason = classify(row["features"])
            print("   %-5s %6.2f Mb/s -> %-12s  model said %-11s | %s"
                  % (row.get("protocol"), row.get("observed_rate_mbit") or 0,
                     queue, row.get("model_said"), reason))
        print()


if __name__ == "__main__":
    paths = sys.argv[1:]
    if not paths:
        print("usage: policy-classifier.py <labelled .jsonl> ...")
        raise SystemExit(2)
    evaluate(paths)
    examples(paths)
