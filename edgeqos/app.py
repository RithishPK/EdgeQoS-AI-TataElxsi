import argparse
import collections
import csv
import json
import os
import platform
import random
import signal
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from . import boost, dataset, metrics
from .baseline import classify_baseline
from .capacity import Estimator
from .flows import Collector, Flow, classify
from .intent import Overrides
from .model import FEATURES, LABELS, Forest, load_model, read_csv, synthetic, train
from .features import BEHAVIORS, FEATURES_V2, FEATURES_V3, QUEUE_FOR_BEHAVIOR
from .policy import Policy, floors, run, validate
from .preflight import inspect
from .capture import SNAPLEN, open_capture
from .control import ModeControl

ROOT=Path(__file__).resolve().parent.parent


def notify(message):
    address=os.environ.get('NOTIFY_SOCKET')
    if not address: return
    if address.startswith('@'): address='\0'+address[1:]
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sock:
        sock.connect(address); sock.sendall(message.encode())


def config(path):
    c=json.loads(Path(path).read_text()); validate(c)
    c["model"]=str((Path(path).resolve().parent/c["model"]).resolve())
    return c


class Service:
    def __init__(self,c):
        self.c=c; self.collector=Collector(c); self.policy=Policy(c)
        self.stop=threading.Event(); self.lock=threading.Lock()
        self.started=time.monotonic(); self.error=None; self.capture_error=None
        self.model_error=None; self.status={"mode":c["mode"],"started":time.time()}
        try: self.forest=load_model(c["model"])
        except Exception as e: self.forest=None; self.model_error=str(e)
        self.sock=None; self.http=None
        self.cached_snapshot=None; self.capture_info={}
        self.capture_interval={"packets":0,"drops":0,"drop_percent":0.0}
        self.control=ModeControl(c)
        self.overrides=Overrides(c["lan"])
        # Shaping is per direction: the uplink carries upload, the LAN interface download.
        self.estimators={c["uplink"]:Estimator(c["upload_mbit"]),
                         c["downlink"]:Estimator(c["download_mbit"])}
        self.queues={}; self.capacity_error=None
        self.previous_queues={}; self.measured_at=None
        self.probe=None; self.probe_error=None

    def capture(self):
        try:
            while not self.stop.is_set():
                try:
                    packet=self.sock.recv(SNAPLEN) # bounded header prefix; no payload storage
                    with self.lock: self.collector.ingest(packet)
                except socket.timeout: continue
        except Exception as e:
            self.capture_error=str(e); self.stop.set()

    def snapshot(self):
        # HTTP readers reuse one snapshot; they never block the packet reader
        # on filesystem I/O, feature computation or repeated sorting.
        if self.cached_snapshot is None:
            return self.build_snapshot()
        return dict(self.cached_snapshot, uptime_seconds=round(time.monotonic()-self.started,1),
                    mode=self.status['mode'],control=self.control.state(self.status['mode']),
                    demo_model_applies=self.c['allow_demo_model'],
                    overrides=self.overrides.report(),
                    error=self.error,capture_error=self.capture_error,model_error=self.model_error,
                    capacity_error=self.capacity_error)

    def build_snapshot(self):
        leases=self.collector.read_leases()
        with self.lock:
            flow_copies=[f.copy_for_analysis() for f in sorted(self.collector.flows.values(),key=lambda f:f.bytes,reverse=True)[:100]]
            clients=self.collector.clients_snapshot(leases=leases)
            counters=dict(self.collector.counters); active_flows=len(self.collector.flows)
        flows=[f.summary() for f in flow_copies]
        upload_rate=round(sum(c['upload_mbit'] for c in clients),3)
        download_rate=round(sum(c['download_mbit'] for c in clients),3)
        return dict(self.status, uptime_seconds=round(time.monotonic()-self.started,1),
                        control=self.control.state(self.status['mode']),
                        counters=counters,active_flows=active_flows,
                        sampled_at=time.time(),capture=dict(self.capture_info),
                        capture_interval=dict(self.capture_interval),
                        flows=flows,clients=clients,total_upload_mbit=upload_rate,
                        total_download_mbit=download_rate,
                        total_observed_mbit=round(upload_rate+download_rate,3),
                        error=self.error,capture_error=self.capture_error,model_error=self.model_error,
                        capacity_error=self.capacity_error,
                        model_provenance=self.forest.data.get("provenance") if self.forest else "unavailable",
                        scheduler=self.c.get("scheduler","htb"), model_kind=self.forest.data.get("kind","random-forest") if self.forest else "unavailable",
                        demo_model_applies=self.c["allow_demo_model"],
                        upload_mbit=self.c["upload_mbit"],download_mbit=self.c["download_mbit"],
                        shaping=dict(self.queues),fairness=self.fairness(clients),
                        latency=self.probe.report() if self.probe else
                            dict(error=self.probe_error or "No uplink next hop to probe",samples=0),
                        baseline_comparison=self.comparison(flows),
                        overrides=self.overrides.report(),
                        coverage="IPv4 TCP/UDP routed %s <-> %s. Same-subnet peers bypass routing."
                                 % (self.c["downlink"],self.c["uplink"]),
                        field_accuracy_validated=False)

    def start_probe(self):
        """One small echo per interval to the uplink next hop; the path, not a load."""
        try:
            target=metrics.default_gateway(self.c["uplink"])
        except Exception as exc:
            self.probe_error=str(exc); return
        if not target:
            self.probe_error=f"No default route via {self.c['uplink']}"; return
        try:
            self.probe=metrics.LatencyProbe(target,max(1.0,float(self.c["interval"]))).start()
        except OSError as exc:
            self.probe_error=f"Latency probe unavailable: {exc}"

    def requeue(self):
        """Force every live flow back through classification on the next pass."""
        with self.lock:
            for flow in self.collector.flows.values(): flow.classified_packets=-1

    def measure(self):
        """Read back what the kernel scheduled, then re-rate if the link moved.

        HTB counters are cumulative and carry no rate estimator, so throughput is
        the delta between this poll and the last one over the elapsed wall time.
        The first poll after setup therefore reports zero rather than a guess.
        """
        if self.c.get("scheduler")=="cake":
            self.queues={"scheduler":"cake","note":"CAKE uses fixed configured rates; HTB class metrics are unavailable."}
            return
        observed={}
        now=time.monotonic()
        elapsed=now-self.measured_at if self.measured_at else 0.0
        self.measured_at=now
        for dev,direction in ((self.c["uplink"],"upload"),(self.c["downlink"],"download")):
            queues=metrics.queue_stats(dev)
            estimator=self.estimators[dev]
            if not queues:
                self.previous_queues.pop(dev,None)
                observed[direction]=dict(device=dev,queues={},shaped=False,
                                         capacity=estimator.report())
                continue
            measured=metrics.rates(self.previous_queues.get(dev),queues,elapsed)
            self.previous_queues[dev]=queues
            achieved=round(sum(measured.values()),3)
            backlog=sum(q["backlog_packets"] for q in queues.values())
            estimator.observe(achieved,backlog,now)
            wanted=estimator.decide(now) if self.c.get("auto_capacity",True) else None
            if wanted is not None:
                try: self.policy.rerate(dev,wanted)
                except Exception as exc: self.capacity_error=str(exc)
            floor=floors(estimator.applied)
            observed[direction]=dict(device=dev,shaped=True,
                queues={name:dict(stats,rate_mbit=measured[name]) for name,stats in queues.items()},
                achieved_mbit=achieved,backlog_packets=backlog,interval_seconds=round(elapsed,3),
                starved_queues=metrics.starvation(queues,measured,floor),
                guaranteed_floor_mbit=floor,capacity=estimator.report())
        self.queues=observed

    def fairness(self,clients):
        """Per-client equality of achieved download share; None while idle."""
        return dict(download=metrics.jain_fairness([c["download_mbit"] for c in clients]),
                    upload=metrics.jain_fairness([c["upload_mbit"] for c in clients]),
                    clients=len(clients),
                    method="Jain's index over 10s per-client throughput; 1.0 is equal shares")

    def comparison(self,flows):
        """How often the model and the port table disagree, and in which direction.

        This is the only honest way to show what the model adds: both arms score
        the same live flows, so a disagreement is visible rather than asserted.
        Neither arm is ground truth here, so this reports divergence, not accuracy.
        """
        undecided=("warmup","fallback","model-unavailable")
        # An operator override is not the model disagreeing with the port table, and
        # counting it as one would credit the model for a human's decision.
        decided=[f for f in flows
                 if f["source"] not in undecided and not f["source"].startswith("operator")]
        overridden=sum(1 for f in flows if f["source"].startswith("operator"))
        moves=collections.Counter()
        for f in decided:
            if not f["agrees_with_baseline"]:
                moves[f"{f['baseline_label']} -> {f['label']}"]+=1
        disagreements=sum(1 for f in decided if not f["agrees_with_baseline"])
        return dict(decided_flows=len(decided),operator_overridden_flows=overridden,
            agreements=len(decided)-disagreements,disagreements=disagreements,
            divergence_percent=round(100*disagreements/len(decided),2) if decided else None,
            reclassifications=dict(moves.most_common(8)),
            note="Port table vs behavioral model on identical flows, operator overrides excluded. "
                 "Divergence is not accuracy.")

    def classify_pending(self):
        with self.lock:
            self.collector.expire()
            pending=[(f,f.copy_for_analysis()) for f in self.collector.flows.values()
                     if f.packets!=f.classified_packets]
        # Inference works on isolated copies while new packets keep arriving.
        for original,copy in pending:
            classify(copy,self.forest,self.c["confidence"],self.c["allow_demo_model"],self.overrides)
            with self.lock:
                if self.collector.flows.get(original.key) is not original: continue
                original.label=copy.label; original.confidence=copy.confidence
                original.source=copy.source; original.predicted_label=copy.predicted_label
                original.baseline_label=copy.baseline_label; original.baseline_rule=copy.baseline_rule
                original.intent_expires_in=copy.intent_expires_in
                original.classified_packets=copy.packets
        with self.lock:
            return [f.copy_for_analysis() for f in self.collector.flows.values()]

    def apply_mode_request(self):
        enabled=self.control.take()
        if enabled is None: return
        failure=None
        try:
            if enabled:
                if self.forest is None: raise RuntimeError('No usable classification model is loaded')
                if self.c['mode']!='enforce':
                    live=inspect(self.c)
                    if live['failures']: raise RuntimeError('Preflight: '+', '.join(live['failures']))
                    self.policy.setup()
                # The dashboard explicitly labels synthetic-model AI as a demo.
                self.c['allow_demo_model']=self.forest.data.get('provenance')=='synthetic-demo'
                self.c['mode']='enforce'
            else:
                self.policy.rollback()
                self.c['mode']='monitor'; self.c['allow_demo_model']=False
            self.status['mode']=self.c['mode']
        except Exception as exc:
            failure=str(exc)
            # Never claim AI OFF until owned shaping really has been removed.
            try:
                self.policy.rollback()
            except Exception as cleanup:
                self.error=f'Mode change failed: {exc}; cleanup failed: {cleanup}'
                self.status['mode']='recovery-needed'
                raise RuntimeError(self.error) from cleanup
            self.c['mode']='monitor'; self.c['allow_demo_model']=False
            self.status['mode']='monitor'
        finally:
            self.requeue()
            self.control.finish(failure)

    def serve(self):
        service=self
        class Handler(BaseHTTPRequestHandler):
            def control_authorized(self):
                return service.control.authorized(self.client_address[0],self.headers.get('Host',''),
                    self.connection.getsockname(),self.headers.get('Origin'),self.headers.get('Sec-Fetch-Site'))

            def json_reply(self,code,data):
                body=json.dumps(data).encode()
                self.send_response(code); self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)))
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                self.end_headers(); self.wfile.write(body)

            def read_json(self,limit):
                length=int(self.headers.get('Content-Length','0'))
                if not 1<=length<=limit: raise ValueError('Invalid request size')
                self.connection.settimeout(3)
                data=json.loads(self.rfile.read(length))
                if not isinstance(data,dict): raise ValueError('Expected a JSON object')
                return data

            def post_control(self):
                data=self.read_json(128)
                if set(data)!={'ai_enabled'}: raise ValueError('Expected ai_enabled only')
                service.control.request(data['ai_enabled'])
                return self.json_reply(202,{'accepted':True})

            def post_intent(self):
                data=self.read_json(256)
                if data.get('clear'):
                    if set(data)!={'clear','client'}: raise ValueError('Expected client and clear only')
                    return self.json_reply(200,{'intents':service.overrides.clear_intent(data['client'])})
                if set(data)-{'client','queue','ttl_seconds','note'} or not {'client','queue','ttl_seconds'}<=set(data):
                    raise ValueError('Expected client, queue, ttl_seconds and optional note')
                intents=service.overrides.add_intent(data['client'],data['queue'],
                                                     data['ttl_seconds'],data.get('note',''))
                service.requeue()
                return self.json_reply(200,{'intents':intents})

            def post_correction(self):
                data=self.read_json(256)
                required={'remote','protocol','remote_port'}
                if data.get('clear'):
                    if set(data)!=required|{'clear'}: raise ValueError('Expected remote, protocol, remote_port and clear')
                    return self.json_reply(200,{'corrections':service.overrides.clear_correction(
                        data['remote'],data['protocol'],data['remote_port'])})
                if set(data)-(required|{'queue','note'}) or not (required|{'queue'})<=set(data):
                    raise ValueError('Expected remote, protocol, remote_port, queue and optional note')
                corrections=service.overrides.add_correction(data['remote'],data['protocol'],
                    data['remote_port'],data['queue'],data.get('note',''))
                service.requeue()
                return self.json_reply(200,{'corrections':corrections})

            def do_POST(self):
                routes={'/api/control':self.post_control,'/api/intent':self.post_intent,
                        '/api/correction':self.post_correction}
                handler=routes.get(self.path)
                if handler is None: return self.json_reply(404,{'error':'Not found'})
                # Overrides change what the kernel does, so they need the control bar.
                if not self.control_authorized() or not service.control.valid_token(self.headers.get('X-EdgeQoS-Token')):
                    return self.json_reply(403,{'error':'Controls are available only on the designated admin laptop or Pi dashboard'})
                if self.headers.get('Content-Type','').split(';')[0]!='application/json':
                    return self.json_reply(415,{'error':'Expected application/json'})
                try:
                    return handler()
                except (ValueError,TypeError,TimeoutError,KeyError) as exc:
                    return self.json_reply(400,{'error':str(exc)})
                except RuntimeError as exc:
                    return self.json_reply(409,{'error':str(exc)})

            def do_GET(self):
                if self.path=='/api/control':
                    if not self.control_authorized(): return self.json_reply(403,{'error':'View-only device'})
                    return self.json_reply(200,dict(service.control.state(service.status['mode']),token=service.control.token))
                elif self.path=='/api/overrides':
                    if not self.control_authorized(): return self.json_reply(403,{'error':'View-only device'})
                    return self.json_reply(200,service.overrides.report())
                elif self.path in ("/api/status","/healthz"):
                    data=service.snapshot()
                    code=503 if data["error"] or data["capture_error"] else 200
                    body=json.dumps(data).encode(); kind="application/json"
                elif self.path=="/":
                    code=200; body=(ROOT/"web/index.html").read_bytes(); kind="text/html; charset=utf-8"
                else:
                    code=404; body=b"Not found"; kind="text/plain"
                self.send_response(code); self.send_header("Content-Type",kind)
                self.send_header("Content-Length",str(len(body)))
                self.send_header("Cache-Control","no-store")
                self.send_header("X-Content-Type-Options","nosniff")
                self.send_header("Content-Security-Policy","default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
                self.end_headers(); self.wfile.write(body)
            def log_message(self,*args): pass
        self.http=ThreadingHTTPServer((self.c["listen"],self.c["port"]),Handler)
        self.http.daemon_threads=True; self.http.timeout=1
        threading.Thread(target=self.http.serve_forever,daemon=True).start()

    def main(self):
        # Open resources before making any QoS changes; failures leave routing alone.
        self.sock,self.capture_info=open_capture(self.c["downlink"])
        self.start_probe()
        self.cached_snapshot=self.build_snapshot()
        self.serve()
        try:
            if self.c["mode"]=="enforce":
                live=inspect(self.c)
                if live["failures"]: raise RuntimeError("Preflight failed: "+str(live["failures"]))
                self.policy.setup()
            threading.Thread(target=self.capture,daemon=True).start()
            notify('READY=1')
            while not self.stop.wait(self.c["interval"]):
                notify('WATCHDOG=1')
                self.apply_mode_request()
                flows=self.classify_pending()
                if self.c["mode"]=="enforce":
                    self.policy.update(flows)
                    self.measure()
                else:
                    # Counters restart with the next setup(), so stale deltas are useless.
                    self.queues={}; self.previous_queues={}; self.measured_at=None
                notify('WATCHDOG=1')
                try:
                    stats=self.sock.getsockopt(263,6,8) # SOL_PACKET, PACKET_STATISTICS; resets on read
                    packets,drops=struct.unpack("II",stats)
                    self.capture_interval=dict(packets=packets,drops=drops,
                        drop_percent=round(100*drops/packets,3) if packets else 0.0)
                    with self.lock:
                        self.collector.counters["socket_drops"]+=drops
                        self.collector.counters["socket_packets"]=self.collector.counters.get("socket_packets",0)+packets
                except OSError: pass
                self.cached_snapshot=self.build_snapshot()
                state=Path(self.c["state_dir"]); state.mkdir(parents=True,exist_ok=True)
                tmp=state/"status.tmp"; tmp.write_text(json.dumps(self.snapshot())); tmp.replace(state/"status.json")
            if self.capture_error: raise RuntimeError(self.capture_error)
        except Exception as e:
            self.error=str(e)
            self.status["mode"]="recovery-needed" if self.policy.state.exists() else "failed-open"
            raise
        finally:
            self.stop.set()
            if self.probe: self.probe.stop.set()
            if self.policy.state.exists(): self.policy.rollback()
            if self.http: self.http.shutdown(); self.http.server_close()
            if self.sock: self.sock.close()


def benchmark(model,n=10000):
    rng=random.Random(87); samples=synthetic(88,500)
    if model.data['features'] in (FEATURES_V2,FEATURES_V3):
        samples=[(x+[1/max(1,x[2]),.01,.5,.2,x[0]*x[2],.4],y) for x,y in samples]
    if model.data['features']==FEATURES_V3: samples=[(x+[443.0],y) for x,y in samples]
    start=time.perf_counter(); cpu=time.process_time()
    for i in range(n): model.predict(samples[i%len(samples)][0])
    elapsed=time.perf_counter()-start
    result={"platform":platform.platform(),"machine":platform.machine(),"python":platform.python_version(),
            "iterations":n,"elapsed_seconds":elapsed,"inferences_per_second":n/elapsed,
            "mean_inference_us":elapsed/n*1e6,"cpu_seconds":time.process_time()-cpu,
            "model_provenance":model.data.get("provenance"),"input":"synthetic behavior vectors",
            "network_throughput_measured":False}
    try:
        import resource
        result["max_rss_kib"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except ImportError: pass
    return result


def evaluate(model, rows):
    """Score the model and the port table on identical held-out flows.

    Both arms are judged on the queue they would actually have put the flow in,
    not on the label, because the queue is what changes a packet's fate. The
    per-packet-count breakdown is reported because accuracy on a flow seen for
    eight packets is not the same claim as accuracy on a settled window.
    """
    labels=model.data["labels"]
    matrix=[[0]*len(labels) for _ in labels]
    queue_ok=baseline_ok=0
    failures=collections.Counter()
    buckets=collections.defaultdict(lambda:[0,0])
    for row in rows:
        predicted,_score=model.predict(row["features"])
        matrix[row["label"]][labels.index(predicted)]+=1
        truth=QUEUE_FOR_BEHAVIOR[row["behavior"]]
        correct=QUEUE_FOR_BEHAVIOR[predicted]==truth
        queue_ok+=correct
        name="8-24 packets" if row["packets"]<25 else "25-200 packets" if row["packets"]<200 else "200+ packets"
        buckets[name][0]+=correct; buckets[name][1]+=1
        probe=Flow(key=("0.0.0.0","0.0.0.0",row["protocol"],row["client_port"],row["remote_port"]),start=0,last=0)
        queue,rule=classify_baseline(probe)
        baseline_ok+=queue==truth
        if queue!=truth:
            failures[f"{row['behavior']} shaped as {queue} by port rule '{rule}'"]+=1
    n=len(rows)
    return dict(test_rows=n,labels=labels,confusion_matrix=matrix,
        behavior_accuracy=round(sum(matrix[i][i] for i in range(len(labels)))/n,4),
        queue_accuracy=round(queue_ok/n,4),
        port_baseline_queue_accuracy=round(baseline_ok/n,4),
        queue_accuracy_by_observation={k:round(v[0]/v[1],4) for k,v in sorted(buckets.items())},
        port_baseline_failures=dict(failures.most_common(10)),
        accuracy_basis="held-out synthetic behavioral windows generated by edgeqos.dataset",
        real_application_accuracy_established=False)


def train_model(args):
    """Fit and score a model, writing the artifact and its report side by side."""
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True)
    if args.csv:
        if not args.test_csv:
            raise SystemExit("Supply --test-csv from independent capture sessions for real labelled training")
        model=train(read_csv(args.csv),provenance="user-labelled")
        testing=read_csv(args.test_csv)
        out.write_text(json.dumps(model.data,separators=(",",":")))
        matrix=[[0]*4 for _ in range(4)]
        for x,y in testing: matrix[y][LABELS.index(model.predict(x)[0])]+=1
        report=dict(provenance=model.data["provenance"],kind="random-forest",
                    split="supplied independent test CSV",test_rows=len(testing),
                    accuracy=sum(matrix[i][i] for i in range(4))/len(testing),
                    labels=LABELS,confusion_matrix=matrix,
                    real_application_accuracy_established=False)
    else:
        rows=dataset.build_flows(args.seed,args.rows)
        random.Random(args.seed).shuffle(rows)
        cut=int(len(rows)*.8)
        training=[(r["features"],r["label"]) for r in rows[:cut]]
        provenance="synthetic-behavioral"
        if args.kind=="boost":
            model=boost.train(training,rounds=args.rounds,depth=args.depth,
                              seed=args.seed,provenance=provenance)
        else:
            model=train(training,seed=args.seed,provenance=provenance,
                        features=FEATURES_V2,labels=BEHAVIORS)
        out.write_text(json.dumps(model.data,separators=(",",":")))
        report=dict(provenance=provenance,kind=model.data.get("kind","random-forest"),
                    split="seeded 80/20 over generated packet-level windows",
                    training_rows=len(training),**evaluate(model,rows[cut:]))
    report["model_bytes"]=out.stat().st_size
    out.with_suffix(".report.json").write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


def main():
    p=argparse.ArgumentParser(description="Tata Elxsi EdgeQoS prototype")
    p.add_argument("--config",default=str(ROOT/"config.json"))
    sub=p.add_subparsers(dest="action",required=True)
    for name in ("preflight","run","rollback","benchmark","plan"): sub.add_parser(name)
    tr=sub.add_parser("train")
    tr.add_argument("--csv"); tr.add_argument("--test-csv")
    tr.add_argument("--kind",choices=("boost","forest"),default="boost")
    tr.add_argument("--rows",type=int,default=700,help="generated windows per behavior")
    tr.add_argument("--rounds",type=int,default=40); tr.add_argument("--depth",type=int,default=4)
    tr.add_argument("--seed",type=int,default=42)
    tr.add_argument("--output",default=str(ROOT/"models/behavior-boost.json"))
    args=p.parse_args(); c=config(args.config)
    if args.action=="train":
        train_model(args)
    elif args.action=="preflight":
        result=inspect(c); print(json.dumps(result,indent=2)); return int(bool(result["failures"]))
    elif args.action=="rollback": Policy(c).rollback()
    elif args.action=="benchmark": print(json.dumps(benchmark(Forest.load(c["model"])),indent=2))
    elif args.action=="plan": print(Policy(c).nft_base())
    else:
        service=Service(c)
        for sig in (signal.SIGTERM,signal.SIGINT): signal.signal(sig,lambda *_:service.stop.set())
        service.main()
    return 0
