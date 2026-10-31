#!/bin/sh
# Put EDGEqos into one cell of the CAKE/HTB matrix, then PROVE which qdisc is live.
# Run as root on the Pi:  sudo sh /tmp/edgeqos-cell.sh cake-ai-off
#
# Every cell except baseline shapes at the same configured caps, and
# auto_capacity is forced off so the estimator cannot move the rate mid-run.
set -e
CFG=/etc/edgeqos/config.json
CELL="$1"

case "$CELL" in
  baseline)    SCHED=cake; CAKE_AI=false; HTB_AI=false; AI=false ;;
  htb-ai-off)  SCHED=htb;  CAKE_AI=false; HTB_AI=false; AI=true  ;;
  htb-ai-on)   SCHED=htb;  CAKE_AI=false; HTB_AI=true;  AI=true  ;;
  cake-ai-off) SCHED=cake; CAKE_AI=false; HTB_AI=true;  AI=true  ;;
  cake-ai-on)  SCHED=cake; CAKE_AI=true;  HTB_AI=true;  AI=true  ;;
  *) echo "usage: $0 <baseline|htb-ai-off|htb-ai-on|cake-ai-off|cake-ai-on>" >&2; exit 2 ;;
esac

python3 - "$CFG" "$SCHED" "$CAKE_AI" "$HTB_AI" <<'PYEOF'
import json, sys
path, sched, cake_ai, htb_ai = sys.argv[1:5]
c = json.load(open(path))
c["scheduler"] = sched
c["cake_ai"] = cake_ai == "true"
c["htb_ai"] = htb_ai == "true"
c["auto_capacity"] = False      # pin the shaper; no mid-run re-rating
c["mode"] = "monitor"           # always come up unshaped, then toggle explicitly
json.dump(c, open(path, "w"), indent=2)
PYEOF

# An nft table with no /run/edgeqos/policy.json beside it is an orphan:
# rollback() returns early when the state file is missing, so it never removes
# the table, and every later setup() aborts with "Reserved nft table already
# exists". Clear it here, exactly as rollback would, and only when it is ours.
if nft list table inet edgeqos >/dev/null 2>&1 && [ ! -f /run/edgeqos/policy.json ]; then
  if nft list table inet edgeqos 2>/dev/null | grep -q 'Tata EdgeQoS owned v1'; then
    echo "clearing orphaned nft table (no policy.json present)"
    nft delete table inet edgeqos
  else
    echo "FAIL: inet edgeqos exists but is not ours; refusing to touch it" >&2
    exit 1
  fi
fi

# The unit allows 3 starts per 60 s; clearing the counter keeps a run of cells
# from tripping it and leaving the service down.
systemctl reset-failed edgeqos 2>/dev/null || true
systemctl restart edgeqos

i=0
while [ $i -lt 30 ]; do
  if curl -sf -m 2 http://127.0.0.1:8080/api/status >/dev/null 2>&1; then break; fi
  i=$((i + 1)); sleep 1
done
if [ $i -ge 30 ]; then echo "FAIL: service did not come back" >&2; exit 1; fi

if [ "$AI" = true ]; then
  TOKEN=$(curl -s -m 5 http://127.0.0.1:8080/api/control \
          | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
  curl -s -m 10 -X POST -H "X-EdgeQoS-Token: $TOKEN" \
       -H 'Content-Type: application/json' -d '{"ai_enabled":true}' \
       http://127.0.0.1:8080/api/control >/dev/null
  sleep 12   # policy applies on the next 2 s loop tick; let rates settle
fi

echo "===== CELL $CELL ====="
for d in eth0 wlan0; do
  printf -- '-- %s --\n' "$d"
  /usr/sbin/tc qdisc show dev "$d" | head -3
done
curl -s -m 5 http://127.0.0.1:8080/api/status | python3 -c '
import sys, json
d = json.load(sys.stdin)
want_ai = "'"$AI"'" == "true"
got_ai = bool(d["control"]["ai_enabled"])
print("mode=%s ai=%s scheduler=%s caps=%s/%s error=%s" % (
    d["mode"], got_ai, d["scheduler"],
    d["download_mbit"], d["upload_mbit"], d["error"]))
if d["control"].get("error"):
    print("CONTROL ERROR: %s" % d["control"]["error"])
if got_ai != want_ai:
    # Loud, because a silently unshaped link labelled as a shaped cell is the
    # one failure that would corrupt the comparison without being noticed.
    raise SystemExit("FAIL: wanted ai=%s but the service reports ai=%s" % (want_ai, got_ai))'
