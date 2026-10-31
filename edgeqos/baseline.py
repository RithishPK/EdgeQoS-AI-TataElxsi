"""Deterministic port/protocol classifier: the comparison arm for AI claims.

Intentionally coarse. A static table is what the model has to beat, so letting
this arm peek at behavioral statistics would make the comparison meaningless.
Ports are advisory only: encrypted and non-standard-port traffic is exactly
where a rule table is expected to fall back to best effort.
"""

TCP_RULES = (
    ("interactive", "service", frozenset({22, 23, 53, 3389, 5900})),
    ("realtime", "voice-video", frozenset({5060, 5061})),
    ("bulk", "transfer", frozenset({20, 21, 69, 445, 873, 989, 990, 2049,
                                    6881, 6882, 6883, 6884, 6885, 6886,
                                    6887, 6888, 6889, 51413})),
    ("best_effort", "web", frozenset({80, 443, 8080, 8443})),
)

UDP_RULES = (
    ("interactive", "service", frozenset({53, 123})),
    ("realtime", "voice-video", frozenset({3478, 3479, 3480, 3481, 5004, 5005,
                                           5060, 5061, 19302, 19303, 19304, 19305})),
    ("realtime", "game", frozenset({3074, 3659, 6250, 12000,
                                    27015, 27016, 27031, 27036})),
    ("bulk", "transfer", frozenset({6881, 51413})),
    ("best_effort", "web", frozenset({80, 443})),
)

# Dynamically negotiated RTP/WebRTC media commonly lands in this range.
RTP_RANGE = (16384, 32767)


def classify_baseline(flow):
    """Return (queue, rule) from the 5-tuple alone. No statistics are consulted."""
    rules = UDP_RULES if flow.key[2] == 17 else TCP_RULES
    for port in (flow.key[4], flow.key[3]):
        for queue, rule, ports in rules:
            if port in ports:
                return queue, rule
    if flow.key[2] == 17 and RTP_RANGE[0] <= flow.key[4] <= RTP_RANGE[1]:
        return "realtime", "rtp-range"
    return "best_effort", "default"
