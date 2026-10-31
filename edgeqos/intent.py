"""Operator overrides: short-lived intents and durable misclassification fixes.

Two distinct things, kept distinct on purpose:

* An **intent** is "my call matters for the next 30 minutes". It is scoped to a
  client, it expires on its own, and it is not a statement about the model being
  wrong. Expiry is mandatory rather than optional because an override that
  outlives the reason for it is indistinguishable from a misconfiguration, and
  nobody ever comes back to clear it.

* A **correction** is "this flow is not what you think it is". It is keyed on
  the part of the flow that is stable across reconnects (remote address, port
  and protocol) rather than on the ephemeral client port, which changes on every
  new socket and would make the correction useless immediately.

Both are bounded in count and applied after inference, so the model's own output
is still recorded. A correction never rewrites history: `predicted_label` keeps
what the model said, which is what makes the corrections list usable later as
labelled training evidence instead of just a patch.
"""
import ipaddress
import threading
import time

QUEUES = ("realtime", "interactive", "best_effort", "bulk")
MAX_INTENTS = 16
MAX_CORRECTIONS = 256
MAX_TTL = 6 * 3600
MIN_TTL = 30


def _queue(value):
    if value not in QUEUES:
        raise ValueError(f"Queue must be one of {', '.join(QUEUES)}")
    return value


class Overrides:
    """Thread-safe store consulted by the classifier on every pass."""

    def __init__(self, lan):
        self.net = ipaddress.ip_network(lan)
        self.lock = threading.Lock()
        self.intents = {}
        self.corrections = {}
        self.applied = dict(intent=0, correction=0)

    def _client(self, value):
        address = ipaddress.ip_address(value)
        if address not in self.net:
            raise ValueError("Client must be an address on the managed LAN")
        return str(address)

    def add_intent(self, client, queue, ttl_seconds, note="", now=None):
        now = time.monotonic() if now is None else now
        client = self._client(client)
        queue = _queue(queue)
        ttl = float(ttl_seconds)
        if not MIN_TTL <= ttl <= MAX_TTL:
            raise ValueError(f"TTL must be {MIN_TTL}..{MAX_TTL} seconds")
        if not isinstance(note, str) or len(note) > 80:
            raise ValueError("Note must be a string of at most 80 characters")
        with self.lock:
            self._expire(now)
            if client not in self.intents and len(self.intents) >= MAX_INTENTS:
                raise ValueError("Too many active intents")
            self.intents[client] = dict(queue=queue, expires=now + ttl, note=note,
                                        created=time.time(), ttl_seconds=ttl)
        return self.intent_list(now)

    def clear_intent(self, client, now=None):
        client = self._client(client)
        with self.lock:
            self.intents.pop(client, None)
        return self.intent_list(now)

    def add_correction(self, remote, protocol, remote_port, queue, note=""):
        address = ipaddress.ip_address(remote)
        if address.version != 4:
            raise ValueError("Correction remote must be IPv4")
        protocol = int(protocol)
        remote_port = int(remote_port)
        if protocol not in (6, 17) or not 0 <= remote_port <= 65535:
            raise ValueError("Correction must name TCP or UDP and a valid port")
        queue = _queue(queue)
        if not isinstance(note, str) or len(note) > 80:
            raise ValueError("Note must be a string of at most 80 characters")
        key = (str(address), protocol, remote_port)
        with self.lock:
            if key not in self.corrections and len(self.corrections) >= MAX_CORRECTIONS:
                raise ValueError("Too many corrections")
            self.corrections[key] = dict(queue=queue, note=note, created=time.time(), hits=0)
        return self.correction_list()

    def clear_correction(self, remote, protocol, remote_port):
        key = (str(ipaddress.ip_address(remote)), int(protocol), int(remote_port))
        with self.lock:
            self.corrections.pop(key, None)
        return self.correction_list()

    def _expire(self, now):
        for client in [c for c, i in self.intents.items() if i["expires"] <= now]:
            del self.intents[client]

    def apply(self, flow, now=None):
        """Override the queue the model picked. Returns True if anything changed."""
        now = time.monotonic() if now is None else now
        client, remote, protocol, _sport, dport = flow.key
        with self.lock:
            self._expire(now)
            correction = self.corrections.get((remote, protocol, dport))
            if correction is not None:
                correction["hits"] += 1
                self.applied["correction"] += 1
                flow.label = correction["queue"]
                flow.source = "operator-correction"
                return True
            intent = self.intents.get(client)
            if intent is not None:
                self.applied["intent"] += 1
                flow.label = intent["queue"]
                flow.source = "operator-intent"
                flow.intent_expires_in = round(intent["expires"] - now, 1)
                return True
        return False

    def intent_list(self, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            self._expire(now)
            return [dict(client=client, queue=i["queue"], note=i["note"],
                         ttl_seconds=i["ttl_seconds"],
                         expires_in_seconds=round(i["expires"] - now, 1))
                    for client, i in sorted(self.intents.items())]

    def correction_list(self):
        with self.lock:
            return [dict(remote=key[0], protocol="UDP" if key[1] == 17 else "TCP",
                         remote_port=key[2], queue=c["queue"], note=c["note"], hits=c["hits"])
                    for key, c in sorted(self.corrections.items())]

    def report(self, now=None):
        return dict(intents=self.intent_list(now), corrections=self.correction_list(),
                    applied=dict(self.applied))
