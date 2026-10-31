"""Header-only Ethernet capture on the LAN interface; bounded in-memory flows."""
import ipaddress
import math
import pathlib
import socket
import struct
import time
from dataclasses import dataclass, field, replace
from .baseline import classify_baseline
from .features import Window,WINDOW_SECONDS,FEATURES_V2,FEATURES_V3,QUEUE_FOR_BEHAVIOR


def parse_packet(data):
    if len(data)<14:
        return None
    offset=14; et=struct.unpack_from("!H",data,12)[0]
    for _ in range(2):
        if et not in (0x8100,0x88a8): break
        if len(data)<offset+4: return None
        et=struct.unpack_from("!H",data,offset+2)[0]; offset+=4
    if et != 0x0800 or len(data)<offset+20:
        return None
    verihl=data[offset]; ihl=(verihl&15)*4
    total=struct.unpack_from("!H",data,offset+2)[0]
    frag=struct.unpack_from("!H",data,offset+6)[0]
    proto=data[offset+9]
    if verihl>>4 != 4 or ihl<20 or total<ihl+4 or len(data)<offset+ihl+4 or frag&0x3fff or proto not in (6,17):
        return None
    src=socket.inet_ntoa(data[offset+12:offset+16]); dst=socket.inet_ntoa(data[offset+16:offset+20])
    sport,dport=struct.unpack_from("!HH",data,offset+ihl)
    return src,dst,proto,sport,dport,total


@dataclass
class Flow:
    key: tuple
    start: float
    last: float
    packets: int=0
    bytes: int=0
    up: int=0
    down: int=0
    sumsq: int=0
    label: str="best_effort"
    confidence: float=0
    source: str="warmup"
    predicted_label: str="unknown"
    baseline_label: str="best_effort"
    baseline_rule: str="default"
    intent_expires_in: object=None
    window: Window=field(default_factory=Window)
    previous_window: object=None
    classified_packets: int=0

    def copy_for_analysis(self):
        return replace(self, window=replace(self.window),
                       previous_window=replace(self.previous_window) if self.previous_window else None)

    def add(self, size, upload, now):
        if self.window.n and now-self.window.start>=WINDOW_SECONDS:
            self.previous_window=self.window; self.window=Window()
        self.window.add(size,upload,now)
        self.last=now; self.packets+=1; self.bytes+=size; self.sumsq+=size*size
        if upload: self.up+=size
        else: self.down+=size

    def behavior_features(self):
        w=self.window
        if w.n<8 and self.previous_window is not None and self.last-self.previous_window.last<WINDOW_SECONDS:
            w=self.previous_window
        return w.vector(self.key[2]==17)

    def features(self, now=None):
        duration=max(.1,self.last-self.start)
        mean=self.bytes/max(1,self.packets)
        return [mean, math.sqrt(max(0,self.sumsq/max(1,self.packets)-mean*mean)),
                self.packets/duration,self.up/max(1,self.bytes),float(self.key[2]==17),duration]

    def summary(self):
        return dict(client=self.key[0],remote=self.key[1],protocol="UDP" if self.key[2]==17 else "TCP",
                    client_port=self.key[3],remote_port=self.key[4],packets=self.packets,
                    bytes=self.bytes,up_bytes=self.up,down_bytes=self.down,label=self.label,
                    confidence=round(self.confidence,3),source=self.source,
                    predicted_label=self.predicted_label,
                    baseline_label=self.baseline_label,baseline_rule=self.baseline_rule,
                    agrees_with_baseline=self.label==self.baseline_label,
                    intent_expires_in=self.intent_expires_in,
                    behavior_features=dict(zip(FEATURES_V2,self.behavior_features())),
                    features=dict(zip(["mean_bytes","std_bytes","packets_per_second","up_ratio","udp","duration"],self.features())))


class Collector:
    def __init__(self, config):
        self.net=ipaddress.ip_network(config["lan"])
        self.gateway=config["gateway"]
        self.downlink=config["downlink"]
        self.limit=config["max_flows"]; self.idle=config["idle_seconds"]
        self.flows={}; self.client_stats={}
        self.counters=dict(captured=0, unsupported=0, bypass_or_local=0, evicted=0,
                           socket_drops=0, routed_candidate_bytes=0,
                           routed_upload_bytes=0, routed_download_bytes=0)

    def _record_client(self, client, upload, size, now):
        stat=self.client_stats.get(client)
        if stat is None:
            if len(self.client_stats)>=256:
                oldest=min(self.client_stats,key=lambda ip:self.client_stats[ip]['last_seen'])
                del self.client_stats[oldest]
            stat=dict(upload_bytes=0,download_bytes=0,first_seen=now,last_seen=now,buckets=[])
            self.client_stats[client]=stat
        direction='upload_bytes' if upload else 'download_bytes'
        stat[direction]+=size; stat['last_seen']=now
        bucket=int(now)
        if not stat['buckets'] or stat['buckets'][-1][0]!=bucket:
            stat['buckets'].append([bucket,0,0])
            stat['buckets']=[b for b in stat['buckets'] if now-b[0]<30]
        stat['buckets'][-1][1 if upload else 2]+=size

    def read_leases(self):
        # Use NetworkManager's hotspot DHCP leases for names and assigned IPs.
        leases={}
        lease_file=pathlib.Path('/var/lib/NetworkManager')/('dnsmasq-%s.leases' % self.downlink)
        try:
            for line in lease_file.read_text(errors='replace').splitlines():
                fields=line.split()
                if len(fields)>=4:
                    _expiry,mac,ip,hostname=fields[:4]
                    try:
                        if ipaddress.ip_address(ip) not in self.net: continue
                        if int(_expiry) and int(_expiry)<time.time(): continue
                    except ValueError:
                        continue
                    if hostname=='*' or not hostname: hostname='Unknown device'
                    leases[ip]={'hostname':hostname,'mac':mac}
        except OSError:
            pass
        return leases

    def clients_snapshot(self, now=None, leases=None):
        now=time.monotonic() if now is None else now
        leases=dict(self.read_leases() if leases is None else leases)
        active={}
        for flow in self.flows.values(): active[flow.key[0]]=active.get(flow.key[0],0)+1
        rows=[]
        for client,stat in self.client_stats.items():
            recent=[b for b in stat['buckets'] if now-b[0]<10]
            up=sum(b[1] for b in recent); down=sum(b[2] for b in recent)
            duration=max(1.0,min(10.0,now-stat['first_seen']))
            lease=leases.pop(client,{})
            rows.append(dict(client=client,hostname=lease.get('hostname',''),mac=lease.get('mac',''),upload_bytes=stat['upload_bytes'],
                download_bytes=stat['download_bytes'],upload_window_bytes=up,
                download_window_bytes=down,upload_mbit=round(up*8/duration/1_000_000,3),
                download_mbit=round(down*8/duration/1_000_000,3),
                active_flows=active.get(client,0),last_seen_seconds_ago=round(now-stat['last_seen'],1)))
        # Show connected clients even before they generate routed traffic.
        for ip,lease in leases.items():
            if ipaddress.ip_address(ip) in self.net:
                rows.append(dict(client=ip,hostname=lease['hostname'],mac=lease['mac'],upload_bytes=0,
                    download_bytes=0,upload_window_bytes=0,download_window_bytes=0,
                    upload_mbit=0.0,download_mbit=0.0,active_flows=0,last_seen_seconds_ago=None))
        return sorted(rows,key=lambda row:row['download_mbit'],reverse=True)

    def ingest(self, data, now=None):
        now=time.monotonic() if now is None else now
        self.counters["captured"]+=1
        p=parse_packet(data)
        if p is None:
            self.counters["unsupported"]+=1; return
        src,dst,proto,sp,dp,size=p
        a,b=ipaddress.ip_address(src),ipaddress.ip_address(dst)
        al,bl=a in self.net,b in self.net
        if al==bl or src==self.gateway or dst==self.gateway or a.is_multicast or b.is_multicast or b.is_unspecified or a.is_unspecified or str(b)==str(self.net.broadcast_address):
            self.counters["bypass_or_local"]+=1; return
        key=(src,dst,proto,sp,dp) if al else (dst,src,proto,dp,sp)
        if key not in self.flows:
            if len(self.flows)>=self.limit:
                self.flows.pop(min(self.flows,key=lambda k:self.flows[k].last)); self.counters["evicted"]+=1
            self.flows[key]=Flow(key,now,now)
        self.flows[key].add(size,al,now)
        self.counters['routed_candidate_bytes']+=size
        direction='routed_upload_bytes' if al else 'routed_download_bytes'
        self.counters[direction]+=size
        self._record_client(src if al else dst,al,size,now)

    def expire(self,now=None):
        now=time.monotonic() if now is None else now
        for key in list(self.flows):
            if now-self.flows[key].last>self.idle: del self.flows[key]


def classify(flow, forest, threshold=.7, allow_demo=False, overrides=None):
    """Model decision, then operator overrides. The baseline arm always runs."""
    flow.baseline_label,flow.baseline_rule=classify_baseline(flow)
    flow.intent_expires_in=None
    _predict(flow,forest,threshold,allow_demo)
    if overrides is not None:
        overrides.apply(flow)


def _predict(flow, forest, threshold, allow_demo):
    flow.label="best_effort"; flow.confidence=0; flow.source="fallback"; flow.predicted_label="unknown"
    if flow.key[4] in (53,123) or flow.key[3]==53:
        flow.label="interactive"; flow.source="service-rule"; return
    if flow.packets<8 or flow.last-flow.start<.1:
        flow.source="warmup"; return
    if forest is None:
        flow.source="model-unavailable"; return
    try:
        if forest.data['features'] in (FEATURES_V2,FEATURES_V3) and flow.window.n<8 and (flow.previous_window is None or flow.previous_window.n<8):
            flow.source='warmup'; return
        values=flow.behavior_features() if forest.data['features'] in (FEATURES_V2,FEATURES_V3) else flow.features()
        if forest.data['features']==FEATURES_V3: values=values+[flow.key[4]]
        label,score=forest.predict(values)
        flow.predicted_label=label
        flow.confidence=score
        demo=forest.data.get("provenance")=="synthetic-demo"
        if demo and not allow_demo:
            flow.source="demo-prediction-only"; return
        if score>=threshold:
            flow.label=QUEUE_FOR_BEHAVIOR.get(label,label)
            # Name the ensemble that actually decided, so the dashboard cannot claim
            # a forest made a call that a booster made.
            flow.source="demo-forest" if demo else forest.data.get("kind","random-forest")
        else: flow.source="low-confidence"
    except (ValueError,KeyError,TypeError):
        flow.source="model-error"
