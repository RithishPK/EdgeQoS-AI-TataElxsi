"""Link-capacity estimation for a tethered uplink whose real rate is unknown.

Static HTB rates are wrong on a phone tether: the usable rate moves with radio
conditions, and both failure directions hurt. Set the ceiling too high and the
bottleneck moves into the carrier's buffer where fq_codel cannot see it, so the
latency guarantee silently stops holding. Set it too low and capacity is thrown
away.

So the estimate is built from what the kernel actually managed to send, taken as
a lower bound on capacity, and it only moves when the evidence is strong:

* Growth needs the link to be demonstrably busy, because an idle link proves
  nothing about how fast it could have gone.
* Growth is slow and shrink is fast, which is the right asymmetry when the cost
  of overestimating is a bufferbloat spike.
* Re-rating is rate-limited and gated on a relative-change threshold, because
  every change is a `tc class change` syscall and an HTB burst recomputation.
  A controller that chases noise is worse than a slightly stale one.

The estimate is advisory and clamped to a configured envelope. It can never
raise the ceiling above the operator's declared maximum.
"""
import time

MIN_FLOOR_MBIT = 1.0
BUSY_FRACTION = .85          # offered load this close to the ceiling means "saturated"
GROWTH = .10                 # at most +10% per decision
SHRINK = .35                 # but up to -35%, immediately
SIGNIFICANT = .08            # ignore changes smaller than this, relative
MIN_INTERVAL = 15.0          # seconds between applied re-rates
HEADROOM = .95               # shape just under measured capacity to keep the queue local


class Estimator:
    """One direction of one link: EWMA of achieved throughput with hysteresis."""

    def __init__(self, ceiling_mbit, floor_mbit=MIN_FLOOR_MBIT, alpha=.3):
        self.ceiling = float(ceiling_mbit)
        self.floor = max(MIN_FLOOR_MBIT, min(float(floor_mbit), self.ceiling))
        self.alpha = alpha
        self.applied = float(ceiling_mbit)
        self.estimate = None
        self.peak = 0.0
        self.last_change = 0.0
        self.changes = 0
        self.reason = "initial"

    def observe(self, achieved_mbit, backlog_packets, now=None):
        """Fold one interval of measured throughput into the estimate."""
        now = time.monotonic() if now is None else now
        achieved = max(0.0, float(achieved_mbit))
        self.peak = max(self.peak, achieved)
        saturated = achieved >= self.applied * BUSY_FRACTION or backlog_packets > 0
        if not saturated:
            # An idle link is not evidence of a small link; hold the estimate.
            self.reason = "idle"
            return None
        self.estimate = achieved if self.estimate is None else \
            self.alpha * achieved + (1 - self.alpha) * self.estimate
        return self.estimate

    def target(self):
        """Where the shaper should sit, given the current estimate and bounds."""
        if self.estimate is None:
            return self.applied
        wanted = self.estimate / HEADROOM
        if wanted > self.applied:
            wanted = min(wanted, self.applied * (1 + GROWTH))
        else:
            wanted = max(wanted, self.applied * (1 - SHRINK))
        return max(self.floor, min(self.ceiling, round(wanted, 3)))

    def decide(self, now=None):
        """Return a new rate only when it is both significant and not too soon."""
        now = time.monotonic() if now is None else now
        wanted = self.target()
        if now - self.last_change < MIN_INTERVAL:
            self.reason = "rate-limited"
            return None
        if self.applied <= 0 or abs(wanted - self.applied) / self.applied < SIGNIFICANT:
            self.reason = "within-deadband"
            return None
        self.reason = "grow" if wanted > self.applied else "shrink"
        self.applied = wanted
        self.last_change = now
        self.changes += 1
        return wanted

    def report(self):
        return dict(configured_ceiling_mbit=round(self.ceiling, 3),
                    floor_mbit=round(self.floor, 3),
                    applied_mbit=round(self.applied, 3),
                    estimate_mbit=round(self.estimate, 3) if self.estimate is not None else None,
                    observed_peak_mbit=round(self.peak, 3),
                    changes=self.changes, last_decision=self.reason,
                    method="EWMA of achieved throughput while saturated, "
                           "slow-grow/fast-shrink with deadband")
