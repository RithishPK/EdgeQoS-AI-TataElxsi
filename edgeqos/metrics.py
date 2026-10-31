"""Bounded service-quality measurement: queue depth, latency/jitter/loss, fairness.

Queue figures come from the kernel's own HTB counters, so they describe what was
actually scheduled rather than what the controller intended. The latency probe is
deliberately one small packet per interval: it measures the path, and must never
become load of its own.

Two things about `tc` on Debian bookworm (iproute2 6.1.0) shape this module:

* `tc -j class show` silently ignores `-j` for HTB and prints plain text. Parsing
  only JSON means every metric reads as zero on exactly the platform this runs
  on, so the text form is the primary parser and JSON is the fallback for
  whenever that gets fixed.
* HTB classes carry no rate estimator by default, so there is no bits-per-second
  field to read. Throughput is therefore derived from the delta of the byte
  counter between two polls, which is both always available and more honest
  about the interval it describes.
"""
import json
import os
import re
import socket
import struct
import threading
import time

from .policy import HANDLE, run

# Minor handles are written in hex by tc, exactly as policy.setup() created them.
CLASS_QUEUES = {"10": "realtime", "20": "interactive", "30": "best_effort", "40": "bulk"}
WINDOW = 60
TIMEOUT = 1.0

SENT = re.compile(r"Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+) requeues (\d+)\)")
BACKLOG = re.compile(r"backlog (\S+) (\d+)p")
SIZE = re.compile(r"(\d+(?:\.\d+)?)\s*([a-zA-Z]*)")
UNITS = {"": 1, "b": 1, "k": 1024, "kb": 1024, "m": 1024 ** 2, "mb": 1024 ** 2,
         "g": 1024 ** 3, "gb": 1024 ** 3}
EMPTY = dict(bytes=0, packets=0, drops=0, overlimits=0, requeues=0,
             backlog_bytes=0, backlog_packets=0)


def parse_size(text):
    """tc prints sizes human-readably, so '15Kb' has to mean 15360."""
    match = SIZE.fullmatch(text.strip())
    if not match:
        return 0
    return int(float(match.group(1)) * UNITS.get(match.group(2).lower(), 1))


def parse_class_text(output):
    """Per-handle counters from the plain-text `tc -s class show` dump."""
    classes = {}
    handle = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("class htb "):
            handle = stripped.split()[2]
            classes[handle] = dict(EMPTY)
            continue
        if handle is None:
            continue
        sent = SENT.search(stripped)
        if sent:
            classes[handle].update(bytes=int(sent.group(1)), packets=int(sent.group(2)),
                                   drops=int(sent.group(3)), overlimits=int(sent.group(4)),
                                   requeues=int(sent.group(5)))
            continue
        backlog = BACKLOG.search(stripped)
        if backlog:
            classes[handle].update(backlog_bytes=parse_size(backlog.group(1)),
                                   backlog_packets=int(backlog.group(2)))
    return classes


def parse_class_json(entries):
    """Same counters from the JSON dump, for iproute2 versions that emit it."""
    classes = {}
    for entry in entries if isinstance(entries, list) else []:
        if (entry.get("class") or entry.get("kind")) != "htb":
            continue
        stats = entry.get("stats") or {}
        classes[str(entry.get("handle", ""))] = dict(
            bytes=stats.get("bytes", 0), packets=stats.get("packets", 0),
            drops=stats.get("drops", 0), overlimits=stats.get("overlimits", 0),
            requeues=stats.get("requeues", 0),
            backlog_bytes=stats.get("backlog", 0), backlog_packets=stats.get("qlen", 0))
    return classes


def queue_stats(device):
    """Cumulative per-queue counters for the owned HTB; empty unless enforcing."""
    result = run(["tc", "-s", "-j", "class", "show", "dev", device], check=False)
    if result.returncode:
        return {}
    output = result.stdout or ""
    entries = None
    if output.lstrip().startswith("["):
        try:
            entries = json.loads(output)
        except ValueError:
            entries = None
    raw = parse_class_json(entries) if entries is not None else parse_class_text(output)
    queues = {}
    for handle, stats in raw.items():
        if not handle.startswith(HANDLE):
            continue
        name = CLASS_QUEUES.get(handle.split(":")[-1])
        if name:
            queues[name] = stats
    return queues


def rates(previous, current, elapsed):
    """Mbit/s per queue from counter deltas. A counter reset reads as zero, not as
    a negative spike, because setup/rollback legitimately restarts the counters."""
    if elapsed <= 0:
        return {name: 0.0 for name in current}
    measured = {}
    for name, stats in current.items():
        before = previous.get(name) if previous else None
        delta = stats["bytes"] - before["bytes"] if before else 0
        measured[name] = round(max(0, delta) * 8 / elapsed / 1_000_000, 3)
    return measured


def jain_fairness(values):
    """1.0 is equal shares; 1/n is one client taking everything. None if idle."""
    active = [v for v in values if v > 0]
    if not active:
        return None
    total = sum(active)
    return round(total * total / (len(active) * sum(v * v for v in active)), 4)


def starvation(queues, measured, floor_mbit):
    """Classes that were offered traffic but scheduled below their guaranteed floor.

    Backlog is the evidence that traffic was offered: a class sitting below its
    floor with an empty queue is simply a class nobody is using.
    """
    starved = []
    for name, stats in queues.items():
        if stats["backlog_packets"] and measured.get(name, 0.0) < floor_mbit.get(name, 0) * .5:
            starved.append(name)
    return starved


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


class LatencyProbe:
    """One ICMP echo per interval to a fixed target, with a rolling result window.

    Uses the service's existing CAP_NET_RAW. A failed or unsupported socket is
    reported as an error instead of degrading the rest of the service.
    """

    def __init__(self, target, interval=1.0):
        self.target = target
        self.interval = max(.5, interval)
        self.samples = []
        self.sent = 0
        self.received = 0
        self.error = None
        self.identifier = os.getpid() & 0xFFFF
        self.sequence = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def probe_once(self):
        self.sequence = (self.sequence + 1) & 0xFFFF
        header = struct.pack("!BBHHH", 8, 0, 0, self.identifier, self.sequence)
        payload = struct.pack("!d", time.monotonic())
        packet = struct.pack("!BBHHH", 8, 0, checksum(header + payload),
                             self.identifier, self.sequence) + payload
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        try:
            sock.settimeout(TIMEOUT)
            start = time.monotonic()
            sock.sendto(packet, (self.target, 0))
            with self.lock:
                self.sent += 1
            deadline = start + TIMEOUT
            while time.monotonic() < deadline:
                try:
                    data, _ = sock.recvfrom(128)
                except socket.timeout:
                    return None
                if len(data) < 28:
                    continue
                kind, _code, _sum, ident, seq = struct.unpack("!BBHHH", data[20:28])
                if kind == 0 and ident == self.identifier and seq == self.sequence:
                    rtt = (time.monotonic() - start) * 1000
                    with self.lock:
                        self.received += 1
                        self.samples.append(rtt)
                        del self.samples[:-WINDOW]
                    return rtt
            return None
        finally:
            sock.close()

    def run_forever(self):
        while not self.stop.wait(self.interval):
            try:
                self.probe_once()
            except OSError as exc:
                with self.lock:
                    self.error = str(exc)
                return

    def start(self):
        threading.Thread(target=self.run_forever, daemon=True).start()
        return self

    def report(self):
        with self.lock:
            samples = sorted(self.samples)
            sent, received, error = self.sent, self.received, self.error
            ordered = list(self.samples)
        if not samples:
            return dict(target=self.target, samples=0, sent=sent, error=error,
                        loss_percent=round(100 * (sent - received) / sent, 2) if sent else None)
        deltas = [abs(b - a) for a, b in zip(ordered, ordered[1:])]
        return dict(
            target=self.target, samples=len(samples), sent=sent, error=error,
            rtt_p50_ms=round(samples[len(samples) // 2], 3),
            rtt_p95_ms=round(samples[min(len(samples) - 1, int(len(samples) * .95))], 3),
            rtt_min_ms=round(samples[0], 3), rtt_max_ms=round(samples[-1], 3),
            jitter_ms=round(sum(deltas) / len(deltas), 3) if deltas else 0.0,
            loss_percent=round(100 * (sent - received) / sent, 2) if sent else None)


def default_gateway(device):
    """The uplink next hop: the nearest honest latency reference for the WAN path."""
    result = run(["ip", "-j", "route", "show", "default", "dev", device], check=False)
    if result.returncode:
        return None
    try:
        routes = json.loads(result.stdout or "[]")
    except ValueError:
        return None
    for route in routes if isinstance(routes, list) else []:
        if route.get("gateway"):
            return route["gateway"]
    return None
