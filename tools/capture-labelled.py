#!/usr/bin/env python3
"""Record labelled feature windows from live traffic on this network.

Runs ON THE PI. Addresses the gap that matters most: `bulk` has 261-623 windows
from someone else's 13-second 477 Mb/s LAN transfers, while the Pi actually sees
~20 Mb/s downloads with 1500-byte packets. Features learned from the former need
not occur in the latter.

Why it reads the API instead of capturing packets:

  * The running collector already computes FEATURES_V2 for every live flow and
    exposes them in /api/status as `behavior_features`. Taking them from there
    makes training features **identical to runtime features by construction**,
    rather than identical by careful reimplementation. The brief asks for
    exactly that ("Match training features to the live collector").
  * No raw PCAP is written, so the microSD sees kilobytes, not gigabytes.
  * No payload is read at any point; these are sizes, timing and direction only.

Each run is one SESSION with its own id. Windows from a session must stay
together in a train/validation/test split - they are the same flows observed
repeatedly, so splitting within a session would leak.

Usage on the Pi:

    sudo python3 capture-labelled.py --label bulk \\
        --activity "speedtest download, ASUS laptop, 5GHz, eth0 uplink" \\
        --device 10.42.0.51 --seconds 180

    # then start the activity on that device

Output: /var/lib/edgeqos/labelled/<session>.jsonl
"""
import argparse
import json
import os
import socket
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, "/opt/tata-edgeqos")
try:
    from edgeqos.features import FEATURES_V2
except Exception:
    # Keep working even if run outside the package; order must match training.
    FEATURES_V2 = ['mean_bytes', 'std_bytes', 'packets_per_second', 'up_ratio', 'udp',
                   'duration', 'mean_iat', 'std_iat', 'small_ratio', 'large_ratio',
                   'bytes_per_second', 'direction_switch_ratio']

OUT_DIR = Path("/var/lib/edgeqos/labelled")
API = "http://127.0.0.1:8080/api/status"
LABELS = ("bulk", "streaming", "gaming", "realtime", "interactive")


def status():
    with urllib.request.urlopen(API, timeout=4) as r:
        return json.load(r)


def vector(flow):
    """FEATURES_V2 in training order, or None if the collector has not filled it."""
    features = flow.get("behavior_features") or {}
    if not features:
        return None
    try:
        return [float(features[name]) for name in FEATURES_V2]
    except (KeyError, TypeError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, choices=LABELS)
    ap.add_argument("--activity", required=True,
                    help="what is actually running, in words, for provenance")
    ap.add_argument("--device", required=True, help="client IP generating the activity")
    ap.add_argument("--seconds", type=float, default=180.0)
    ap.add_argument("--min-mbit", type=float, default=0.5,
                    help="ignore flows below this rate: background chatter is not the label")
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    session = "%s-%s-%d" % (args.label, args.device.replace(".", "_"), int(time.time()))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / (session + ".jsonl")

    try:
        first = status()
    except Exception as exc:
        print("cannot reach the dashboard API: %s" % exc, file=sys.stderr)
        return 2
    if first.get("mode") != "enforce":
        print("note: QoS is %s, so these windows describe UNSHAPED traffic"
              % first.get("mode"))

    conditions = dict(
        scheduler=first.get("scheduler"),
        model_priorities=first.get("model_priorities"),
        mode=first.get("mode"),
        download_mbit=first.get("download_mbit"),
        upload_mbit=first.get("upload_mbit"),
        uplink=(first.get("coverage") or "").split("<->")[-1].strip().rstrip("."),
        host=socket.gethostname(),
    )

    print("session  : %s" % session)
    print("label    : %s" % args.label)
    print("activity : %s" % args.activity)
    print("device   : %s" % args.device)
    print("condition: %s" % conditions)
    print("recording %.0fs; start the activity now" % args.seconds)
    print()

    # A flow's features only change when it has new packets. Recording the same
    # window twice would inflate the dataset with duplicates that look like
    # independent evidence.
    seen = {}
    written = 0
    samples = 0
    deadline = time.time() + args.seconds
    with path.open("w") as fh:
        while time.time() < deadline:
            try:
                snapshot = status()
            except Exception:
                time.sleep(args.interval)
                continue
            samples += 1
            for flow in snapshot.get("flows") or []:
                if flow.get("client") != args.device:
                    continue
                features = flow.get("behavior_features") or {}
                rate_mbit = float(features.get("bytes_per_second") or 0) * 8 / 1e6
                if rate_mbit < args.min_mbit:
                    continue
                key = (flow["remote"], flow["remote_port"], flow["client_port"], flow["protocol"])
                if seen.get(key) == flow["packets"]:
                    continue
                seen[key] = flow["packets"]
                values = vector(flow)
                if values is None:
                    continue
                fh.write(json.dumps(dict(
                    features=values, label=args.label, session=session,
                    group="live:" + session, source="live",
                    activity=args.activity, device=args.device,
                    conditions=conditions,
                    observed_rate_mbit=round(rate_mbit, 3),
                    protocol=flow["protocol"], remote_port=flow["remote_port"],
                    model_said=flow.get("predicted_label"),
                    model_confidence=flow.get("confidence"),
                    recorded_at=time.time(),
                )) + "\n")
                written += 1
            left = deadline - time.time()
            print("\r  %4.0fs left | %d samples | %d windows | %d flows tracked"
                  % (max(0, left), samples, written, len(seen)), end="", flush=True)
            time.sleep(args.interval)

    print()
    print()
    print("wrote %d labelled windows to %s" % (written, path))
    if written == 0:
        print("nothing recorded: was the activity running on %s, and above %.1f Mb/s?"
              % (args.device, args.min_mbit))
    else:
        print("features are FEATURES_V2 in training order, taken from the live collector")
        print("keep all windows of session %s in ONE split: they are repeated"
              % session)
        print("observations of the same flows, not independent samples")
    return 0


if __name__ == "__main__":
    sys.exit(main())
