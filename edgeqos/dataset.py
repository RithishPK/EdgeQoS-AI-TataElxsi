"""Packet-level synthetic traffic generator for behavioral training data.

Every training vector is produced by replaying a generated packet stream through
the same features.Window used at inference time, so training and serving cannot
drift apart. The streams are shaped from published protocol behavior, not from
captures: they teach the separation between behaviors, not the identity of any
application. Field accuracy still has to be established from real labelled
capture sessions.

Two properties are deliberate, because without them the task becomes trivially
separable and the reported accuracy becomes a lie:

* Parameter ranges overlap. A throttled download really does look like video
  playback; a patch download really does look like bulk; an audio-only call
  really does look like gaming. The generators are allowed to land in each
  other's territory.
* Windows are often truncated. Live classification starts as soon as eight
  packets have been seen, so most decisions are made on a partial window. Half
  the samples are cut short at a random horizon to match.

Deliberately no port feature. The port-table arm in baseline.py is the thing the
model has to beat, and most of this traffic is TCP/443 or QUIC in practice, so
giving the model the port would both leak the baseline's answer and collapse on
encrypted traffic.
"""
import random

from .features import BEHAVIORS, WINDOW_SECONDS, Window

# How often each behavior appears over UDP. QUIC means "web" is no longer a
# reliable TCP signal, so the flag must not become a proxy for the label.
UDP_PROBABILITY = {"gaming": .95, "realtime": .90, "streaming": .35,
                   "interactive": .25, "bulk": .10}
TRUNCATION_PROBABILITY = .5
MIN_PACKETS = 8


def _tick(rng, rate, spread=.18):
    """Inter-arrival time for a nominally constant-rate source."""
    return max(.0005, rng.gauss(1 / rate, spread / rate))


def gaming(rng, emit):
    """Small symmetric datagrams at a fast tick: client input vs server state."""
    rate = rng.uniform(12, 64)
    heavy = rng.random() < .3           # state-heavy titles push bigger updates
    t, upload = 0.0, rng.random() < .5
    while t < WINDOW_SECONDS:
        t += _tick(rng, rate, .22)
        if t >= WINDOW_SECONDS:
            break
        upload = (not upload) if rng.random() < .80 else upload
        if heavy and rng.random() < .18:
            emit(int(rng.uniform(300, 700)), upload, t)
        else:
            emit(int(rng.triangular(48, 230, 105)), upload, t)


def realtime(rng, emit):
    """Conversational audio/video: near-constant pacing, both directions."""
    rate = rng.uniform(20, 110)
    video = rng.random() < .55
    share = video and rng.random() < .35  # screen share skews heavily downstream
    t, upload = 0.0, rng.random() < .5
    while t < WINDOW_SECONDS:
        t += _tick(rng, rate, .09)
        if t >= WINDOW_SECONDS:
            break
        upload = (not upload) if rng.random() < (.25 if share else .70) else upload
        if video and rng.random() < (.5 if share else .22):
            emit(int(rng.uniform(900, 1400)), upload, t)
        else:
            emit(int(rng.uniform(140, 260)), upload, t)


def streaming(rng, emit):
    """Adaptive-bitrate playback: full-size bursts separated by buffer idle."""
    # A near-zero gap is the initial buffer fill, which is indistinguishable
    # from a plain download until the player throttles back.
    gap = rng.choice([rng.uniform(.05, .4), rng.uniform(1.6, 4.0), rng.uniform(1.6, 4.0)])
    burst_rate = rng.uniform(140, 900)
    chunk = rng.uniform(.35, 1.4)
    t = rng.uniform(0, max(.05, gap))
    while t < WINDOW_SECONDS:
        end = min(WINDOW_SECONDS, t + chunk)
        while t < end:
            t += _tick(rng, burst_rate, .35)
            if t >= end:
                break
            if rng.random() < .05:
                emit(int(rng.uniform(52, 120)), True, t)   # upstream ACK
            else:
                emit(int(rng.uniform(1100, 1500)), False, t)
        t += gap


def bulk(rng, emit):
    """Transfer that wants all available capacity, or is throttled trying."""
    rate = rng.choice([rng.uniform(30, 160), rng.uniform(180, 950), rng.uniform(180, 950)])
    sending = rng.random() < .25
    stalls = rng.random() < .3              # congestion or seeding peer churn
    t = 0.0
    while t < WINDOW_SECONDS:
        t += _tick(rng, rate, .30)
        if t >= WINDOW_SECONDS:
            break
        if stalls and rng.random() < .004:
            t += rng.uniform(.2, 1.2)
        if rng.random() < .06:
            emit(int(rng.uniform(52, 140)), not sending, t)
        else:
            emit(int(rng.uniform(1200, 1500)), sending, t)


def interactive(rng, emit):
    """Request/response: sparse, small, direction flips on nearly every packet."""
    rate = rng.uniform(1.5, 30)
    assets = rng.random() < .35            # page load drags down a burst of objects
    t, upload = 0.0, True
    while t < WINDOW_SECONDS:
        t += max(.002, rng.expovariate(rate))
        if t >= WINDOW_SECONDS:
            break
        upload = (not upload) if rng.random() < .85 else upload
        if assets and rng.random() < .3:
            for _ in range(rng.randint(3, 25)):
                t += _tick(rng, rng.uniform(120, 400), .4)
                emit(int(rng.uniform(900, 1480)), False, t)
        elif rng.random() < .07:
            emit(int(rng.uniform(900, 1480)), upload, t)
        else:
            emit(int(rng.uniform(56, 320)), upload, t)
        if rng.random() < .25:
            t += rng.uniform(.05, .9)      # think time


GENERATORS = {"gaming": gaming, "streaming": streaming, "interactive": interactive,
              "bulk": bulk, "realtime": realtime}


# Remote ports, weighted the way home traffic actually lands. These exist only
# so the port-table baseline can be scored on the same flows; they are never
# exposed to the model, which must work when the port says nothing.
PORTS = {
    "gaming": ((.35, (27015, 27016, 3074, 3659)), (.65, "ephemeral")),
    "realtime": ((.30, (3478, 19302, 19305, 5004)), (.55, "rtp"), (1.0, (443,))),
    "streaming": ((.85, (443,)), (1.0, (80, 8080))),
    "bulk": ((.30, (6881, 51413)), (.45, (21, 445, 873)), (1.0, (443, 80))),
    "interactive": ((.22, (22, 3389, 5900)), (.33, (53,)), (1.0, (443,))),
}


def remote_port(behavior, rng):
    roll = rng.random()
    for threshold, choices in PORTS[behavior]:
        if roll <= threshold:
            if choices == "rtp":
                return rng.randint(16384, 32767)
            if choices == "ephemeral":
                return rng.randint(32768, 65535)
            return rng.choice(choices)
    return 443


def sample(behavior, rng):
    """One (feature vector, packet count) pair built by the live Window code."""
    packets = []
    GENERATORS[behavior](rng, lambda size, upload, t: packets.append((size, upload, t)))
    if rng.random() < TRUNCATION_PROBABILITY:
        horizon = rng.uniform(.3, WINDOW_SECONDS)
        packets = [p for p in packets if p[2] <= horizon]
    if len(packets) < MIN_PACKETS:
        return None, len(packets)
    window = Window()
    udp = rng.random() < UDP_PROBABILITY[behavior]
    for size, upload, t in packets:
        window.add(size, upload, t)
    return window.vector(udp), window.n


def build_flows(seed=17, per_class=500):
    """Labelled rows carrying both the behavioral vector and a plausible 5-tuple."""
    rng = random.Random(seed)
    rows = []
    for index, behavior in enumerate(BEHAVIORS):
        produced = attempts = 0
        while produced < per_class and attempts < per_class * 30:
            attempts += 1
            values, packets = sample(behavior, rng)
            if values is None:
                continue
            rows.append(dict(features=values, behavior=behavior, label=index,
                             packets=packets, udp=bool(values[4]),
                             protocol=17 if values[4] else 6,
                             client_port=rng.randint(32768, 65535),
                             remote_port=remote_port(behavior, rng)))
            produced += 1
        if produced < per_class:
            raise RuntimeError(f"{behavior}: generator produced too few valid windows")
    rng.shuffle(rows)
    return rows


def build(seed=17, per_class=500):
    """Balanced behavioral rows as [(features, label_index)] for training."""
    return [(row["features"], row["label"]) for row in build_flows(seed, per_class)]
